FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y default-jre default-jdk git pkg-config uuid uuid-dev freeglut3 freeglut3-dev build-essential cmake clang

COPY . /repo
WORKDIR /repo
RUN ./compile_silice_linux.sh

WORKDIR /repo/tools/stl2raw/build
RUN cmake ..
RUN make -j8
RUN clang++ /repo/mayhem/fuzz_numLinesIn.cpp -fsanitize=fuzzer,address -L /repo/lib/ -llibsilice -lantlr4-runtime -lluabind -llua -o /fuzz

FROM ubuntu:22.04 as package
COPY --from=builder /repo/tools/stl2raw/build/stl2raw /
COPY --from=builder /fuzz /fuzz_numLinesIn
