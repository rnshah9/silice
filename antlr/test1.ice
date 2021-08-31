/*

Copyright 2019, (C) Sylvain Lefebvre and contributors
List contributors with: git shortlog -n -s -- <filename>

MIT license

Permission is hereby granted, free of charge, to any person obtaining a copy of 
this software and associated documentation files (the "Software"), to deal in 
the Software without restriction, including without limitation the rights to 
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all 
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER 
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN 
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

(header_2_M)

*/
// ----------------------- memory_ports.ice -----------
// @sylefeb - Silice standard library
// Memory port interfaces
// 2020-09-03

// single port BRAM

interface bram_port {
  output! addr,
  output! wenable,
  input   rdata,
  output! wdata,
}

// single port BROM

interface brom_port {
  output! addr,
  input   rdata,
}

// dual port BRAM

interface dualport_bram_port0 {
  output! addr0,
  output! wenable0,
  input   rdata0,
  output! wdata0,
}

interface dualport_bram_port1 {
  output! addr1,
  output! wenable1,
  input   rdata1,
  output! wdata1,
}

interface dualport_bram_ports {
  output! addr0,
  output! wenable0,
  input   rdata0,
  output! wdata0,
  output! addr1,
  output! wenable1,
  input   rdata1,
  output! wdata1,
}

// simple dual port BRAM

interface simple_dualport_bram_port0 {
  output! addr0,
  input   rdata0,
}

interface simple_dualport_bram_port1 {
  output! addr1,
  output! wenable1,
  output! wdata1,
}

// ----------------------- end of memory_ports.ice ----

// SL 2020-06-12 @sylefeb
//
// Fun with RISC-V!
// RV32I cpu, see README.md
//
// MIT license, see LICENSE_MIT in Silice repo root

// Clocks
import('../../common/plls/icestick_60.v')


// pre-compilation script, embeds compiled code within a string


// include the processor
// SL 2020-06-12 @sylefeb
//
// Fun with RISC-V!   RV32I cpu, see README.md
//
// MIT license, see LICENSE_MIT in Silice repo root

// --------------------------------------------------
// Processor
// --------------------------------------------------

// bitfield for easier decoding of instructions
bitfield Rtype { uint1 unused1, uint1 sign, uint5 unused2, uint5 rs2, 
                 uint5 rs1,     uint3 op,   uint5 rd,      uint7 opcode}

// --------------------------------------------------
// execute: decoder + ALU
// - decodes instructions
// - performs all integer computations

algorithm execute(
  // instruction, program counter and registers
  input  uint32 instr, input  uint12 pc, input int32 xa, input int32 xb,
  // trigger: pulsed high when the decoder + ALU should start
  input  uint1  trigger, 
  // outputs all information the processor needs to decide what to do next 
  output uint3  op,    output uint5  write_rd, output  uint1  no_rd, 
  output uint1  jump,  output uint1  load,     output  uint1  store,  
  output int32  val,   output uint1  storeVal, output  uint1  working(0),
  output uint32 n,     output uint1  storeAddr, // next address adder
  output uint1  intop, output int32  r,         // integer operations
) {
  uint5  shamt(0);  uint32 cycle(0); // shifter status and cycle counter

  // ==== decode immediates
  int32 imm_u  <: {instr[12,20],12b0};
  int32 imm_j  <: {{12{instr[31,1]}},instr[12,8],instr[20,1],instr[21,10],1b0};
  int32 imm_i  <: {{20{instr[31,1]}},instr[20,12]};
  int32 imm_b  <: {{20{instr[31,1]}},instr[7,1],instr[25,6],instr[8,4],1b0};
  int32 imm_s  <: {{20{instr[31,1]}},instr[25,7],instr[7,5]};

  // ==== decode opcode
  uint5 opcode    <: instr[ 2, 5];
  uint1 AUIPC     <: opcode == 5b00101;  uint1 LUI    <: opcode == 5b01101;
  uint1 JAL       <: opcode == 5b11011;  uint1 JALR   <: opcode == 5b11001;
  uint1 IntImm    <: opcode == 5b00100;  uint1 IntReg <: opcode == 5b01100;
  uint1 Cycles    <: opcode == 5b11100;  uint1 branch <: opcode == 5b11000;
  uint1 regOrImm  <: IntReg  | branch;                    // reg or imm in ALU?
  uint1 pcOrReg   <: AUIPC   | JAL    | branch;           // pc or reg in addr?
  uint1 sub       <: IntReg  & Rtype(instr).sign;         // subtract
  uint1 aluShift  <: (IntImm | IntReg) & op[0,2] == 2b01; // shift requested

  // ==== select next address adder first input
  int32 addr_a    <: pcOrReg ? __signed({1b0,pc[0,10],2b0}) : xa;
  // ==== select ALU second input 
  int32 b         <: regOrImm ? (xb) : imm_i;
    
  // ==== allows to do subtraction and all comparisons with a single adder
  // trick from femtorv32/swapforth/J1
  int33 a_minus_b <: {1b1,~b} + {1b0,xa} + 33b1;
  uint1 a_lt_b    <: (xa[31,1] ^ b[31,1]) ? xa[31,1] : a_minus_b[32,1];
  uint1 a_lt_b_u  <: a_minus_b[32,1];
  uint1 a_eq_b    <: a_minus_b[0,32] == 0;

  // ==== select immediate for the next address computation
  // 'or trick' from femtorv32
  int32 addr_imm  <: (AUIPC  ? imm_u : 32b0) | (JAL         ? imm_j : 32b0)
                  |  (branch ? imm_b : 32b0) | ((JALR|load) ? imm_i : 32b0)
                  |  (store  ? imm_s : 32b0);
  // ==== set decoder outputs depending on incoming instructions
  // load/store?
  load         := opcode == 5b00000;   store        := opcode == 5b01000;   
  // operator for load/store           // register to write to?
  op           := Rtype(instr).op;     write_rd     := Rtype(instr).rd;    
  // do we have to write a result to a register?
  no_rd        := branch  | store  | (Rtype(instr).rd == 5b0);
  // integer operations                // store next address?
  intop        := (IntImm | IntReg);   storeAddr    := AUIPC;  
  // value to store directly           // store value?
  val          := LUI ? imm_u : cycle; storeVal     := LUI     | Cycles;   
  // ==== increment cycle counter
  cycle        := cycle + 1; 
  
  always {
    int32 shift(0);  uint1 j(0); // temp variables for shifter and comparator

    // ====================== ALU
    // shift (one bit per clock)
    if (working) {
      // decrease shift size
      shamt = shamt - 1;
      // shift one bit
      shift = op[2,1] ? (Rtype(instr).sign ? {r[31,1],r[1,31]} 
                          : {__signed(1b0),r[1,31]}) : {r[0,31],__signed(1b0)};      
    } else {
      // start shifting?
      shamt = ((aluShift & trigger) ? __unsigned(b[0,5]) : 0);
      // store value to be shifted
      shift = xa;
    }
    // are we still shifting?
    working = (shamt != 0);

    // all ALU operations
    switch (op) {
      case 3b000: { r = sub ? a_minus_b : xa + b; }            // ADD / SUB
      case 3b010: { r = a_lt_b; } case 3b011: { r = a_lt_b_u; }// SLTI / SLTU
      case 3b100: { r = xa ^ b; } case 3b110: { r = xa | b;   }// XOR / OR
      case 3b001: { r = shift;  } case 3b101: { r = shift;    }// SLLI/SRLI/SRAI
      case 3b111: { r = xa & b; }     // AND
      default:    { r = {32{1bx}}; }  // don't care
    }      

    // ====================== Comparator for branching
    switch (op[1,2]) {
      case 2b00:  { j = a_eq_b;  } /*BEQ */ case 2b10: { j=a_lt_b;} /*BLT*/ 
      case 2b11:  { j = a_lt_b_u;} /*BLTU*/ default:   { j = 1bx; }
    }
    jump = (JAL | JALR) | (branch & (j ^ op[0,1]));
    //                                   ^^^^^^^ negates comparator result

    // ====================== Next address adder
    n = addr_a + addr_imm;

  }
  
}

// --------------------------------------------------
// The Risc-V RV32I CPU itself

algorithm rv32i_cpu(bram_port mem) <onehot> {

  // register file, uses two BRAMs to fetch two registers at once
  bram int32 xregsA[32] = {pad(0)}; bram int32 xregsB[32] = {pad(0)};

  // current instruction
  uint32 instr(0);

  // program counter
  uint12 pc   = uninitialized;
  uint12 next_pc <:: pc + 1; // next_pc tracks the expression 'pc + 1'

  // value that has been loaded from memory
  int32 loaded     = uninitialized;

  // decoder + ALU, executes the instruction and tells processor what to do
  execute exec(
    instr <:: instr, pc <:: pc, xa <: xregsA.rdata, xb <: xregsB.rdata
  );

  // The 'always_before' block is applied at the start of every cycle.
  // This is a good place to set default values, which also indicates
  // to Silice that some variables (e.g. xregsA.wdata) are fully set
  // every cycle, enabling further optimizations.
  // Default values are overriden from within the algorithm loop.
  always_before {
    // decodes values loaded from memory (used when exec.load == 1)
    uint32 aligned <: mem.rdata >> {exec.n[0,2],3b000};
    switch ( exec.op[0,2] ) { // LB / LBU, LH / LHU, LW
      case 2b00:{ loaded = {{24{(~exec.op[2,1])&aligned[ 7,1]}},aligned[ 0,8]}; }
      case 2b01:{ loaded = {{16{(~exec.op[2,1])&aligned[15,1]}},aligned[ 0,16]};}
      case 2b10:{ loaded = aligned;   }
      default:  { loaded = {32{1bx}}; } // don't care (does not occur)
    }
    // what to write on a store (used when exec.store == 1)
    mem.wdata      = xregsB.rdata << {exec.n[0,2],3b000};
    // maintain write enable low (pulses high when needed)
    mem.wenable    = 4b0000; 
    // maintain alu trigger low
    exec.trigger   = 0;
    // maintain register wenable low
    // (pulsed when necessary)
    xregsA.wenable = 0;
  }

  // the 'always_after' block is executed at the end of every cycle
  always_after { 
    // what do we write in register? (pc, alu or val, load is handled separately)
    // 'or trick' from femtorv32
    int32 write_back <: (exec.jump      ? (next_pc<<2)        : 32b0)
                      | (exec.storeAddr ? exec.n[0,14] : 32b0)
                      | (exec.storeVal  ? exec.val            : 32b0)
                      | (exec.load      ? loaded              : 32b0)
                      | (exec.intop     ? exec.r              : 32b0);
    // write back data to both register BRAMs
    xregsA.wdata   = write_back;      xregsB.wdata   = write_back;     
    // xregsB written when xregsA is
    xregsB.wenable = xregsA.wenable; 
    // write to write_rd, else track instruction register
    xregsA.addr    = xregsA.wenable ? exec.write_rd : Rtype(instr).rs1;
    xregsB.addr    = xregsA.wenable ? exec.write_rd : Rtype(instr).rs2;
  }

  // =========== CPU runs forever
  while (1) {

    // data is now available
    instr           = mem.rdata;
    pc              = mem.addr;

++: // wait for register read (BRAM takes one cycle)

    exec.trigger    = 1;

    while (1) { // decode + ALU refresh during the cycle entering the loop

      // this operations loop allows to wait for ALU when needed
      // it is built such that no cycles are wasted    

      // load/store?        
      if (exec.load | exec.store) {   
        // memory address from which to load/store
        mem.addr   = exec.n >> 2;
        // == Store (enabled if exec.store == 1)
        // build write mask depending on SB, SH, SW
        // assumes aligned, e.g. SW => next_addr[0,2] == 2
        mem.wenable = ({4{exec.store}} & { { 2{exec.op[0,2]==2b10} },
                                               exec.op[0,1] | exec.op[1,1], 1b1 
                                        } ) << exec.n[0,2];

++: // wait for data transaction

        // == Load (enabled if exec.load == 1)
        // commit result
        xregsA.wenable = ~exec.no_rd;        
        // restore address to program counter
        mem.addr       = next_pc;
        // exit the operations loop
        break;
        //  instruction read from BRAM and write to register 
        //  occurs as we jump back to loop start

      } else {
        // commit result
        xregsA.wenable = ~exec.no_rd;
        // next instruction address
        mem.addr       = exec.jump ? (exec.n >> 2) : next_pc;
        // ALU done?
        if (exec.working == 0) {
          // yes: all is correct, stop here
          break; 
          //  instruction read from BRAM and write to register 
          //  occurs as we jump back to loop start
        }
      }
    }
  }
}


// --------------------------------------------------
// SOC
// --------------------------------------------------

group bram_io
{
  uint4       wenable(0),
  uint32      wdata(0),
  uint32      rdata(0),
  uint12 addr(0),    // boot address
}

algorithm main( // I guess this is the SOC :-D
  output uint5 leds,
  ) <@cpu_clock> {
  // clock  
  uint1 cpu_clock  = uninitialized;
  pll clk_gen (
    clock_in  <: clock,
    clock_out :> cpu_clock
  ); 




  // ram
  // - intermediate interface to perform memory mapping
  bram_io memio;  
  // - uses template "bram_wmask_byte", that turns wenable into a byte mask
  bram uint32 mem<"bram_wmask_byte">[1536] = {32hC00027F3,32h0017F793,32h00079863,32h00010137,32hFFC10113,32h00C0006F,32h0000F137,32hFFC10113,32h00000097,32h018080E7,32h00000317,32h00830067,32h0000006F,32h00008067,32hFF010113,32h00012623,32h000807B7,32h00F00713,32h00E7A223,32h00200793,32h000806B7,32h00800713,32h0080006F,32h00100793,32h00F6A223,32h00179793,32hFEF74AE3,32hFF5FF06F,32h00080040,32h00080020,32h00080010,32h00080008,32h00080004,pad(uninitialized)};

  // cpu
  rv32i_cpu cpu( mem <:> memio );

  // io mapping
  always {
	  // ---- memory access
    mem.wenable = memio.wenable & {4{~memio.addr[11,1]}}; 
		//                            ^^^^^^^ no BRAM write if in peripheral addresses
    memio.rdata   = mem.rdata;
    mem.wdata     = memio.wdata;
    mem.addr      = memio.addr;
		// ---- peripherals
    // ---- memory mapping to peripherals: writes
    if (/*memio.wenable[0,1] &*/ memio.addr[11,1]) {
      leds      = mem.wdata[0,5] & {5{memio.addr[0,1]}};
    }
  }

  // run the CPU
  () <- cpu <- ();

}

// --------------------------------------------------


// --------------------------------------------------


// --------------------------------------------------

