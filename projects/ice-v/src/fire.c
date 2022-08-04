// MIT license, see LICENSE_MIT in Silice repo root
// @sylefeb 2021
// https://github.com/sylefeb/Silice

#include "oled.h"

unsigned char tbl[32*32]={
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
};

unsigned char pal[] = {0x01,0x01,0x01,0x07,0x01,0x01,0x0b,0x03,0x01,0x11,0x03,
   0x01,0x15,0x05,0x01,0x19,0x07,0x01,0x1d,0x07,0x01,0x27,0x0b,0x01,0x2b,0x0f,
   0x01,0x2f,0x11,0x01,0x31,0x11,0x01,0x37,0x15,0x01,0x37,0x15,0x01,0x35,0x17,
   0x01,0x35,0x17,0x01,0x35,0x19,0x03,0x33,0x1d,0x03,0x33,0x1f,0x03,0x33,0x21,
   0x05,0x31,0x21,0x05,0x31,0x25,0x07,0x2f,0x27,0x07,0x2f,0x27,0x07,0x2f,0x29,
   0x09,0x2f,0x29,0x09,0x2f,0x2b,0x0b,0x2d,0x2b,0x0b,0x2d,0x2d,0x0b,0x33,0x33,
   0x1b,0x37,0x37,0x27,0x3b,0x3b,0x31,0x3f,0x3f,0x3f};

void draw_fire()
{
  for (int v=0;v<128;v++) {
    for (int u=0;u<128;u++) {
      int clr  = tbl[(u>>2) + ((v>>2)<<5)]>>1;
      int clr3 = (clr<<1)+clr;
      const unsigned char *ptr = pal + clr3;
      oled_pix(*ptr++,*ptr++,*ptr++);
    }
  }
}

int rng = 31421;

void update_fire()
{
  // move up
  for (int v=1;v<32;v++) {
    for (int u=0;u<32;u++) {
      int below = tbl[(u) + ((v-1)<<5)];
      int clr   = 0;
      if (below > 3) {
        clr = below-1-(rng&3);
      } else if (below > 1) {
        clr = below-(rng&1);
      }
      rng = ((rng<<5) ^ 6927) + ((rng>>5) ^ u);
      tbl[((u+(rng&3))&31) + (v<<5)] = clr;
    }
  }
}

void main()
{
  *(LEDS) = 7;
  oled_init();
  oled_fullscreen();
  for (int v=0;v<32;v++) {
    for (int u=0;u<32;u++) {
      tbl[u+(v<<5)] = (v == 0) ? 63 : 0;
    }
  }
  int time = 0;
  while (1) {
    update_fire();
    draw_fire();
    ++ time;
    if ((time&63) == 0) {
      // turn off
      for (int u=0;u<32;u++) {
        tbl[u] = 0;
      }
    }
    if ((time&63) == 31) {
      // turn on
      for (int u=0;u<32;u++) {
        tbl[u] = 63;
      }
    }
  }
}
