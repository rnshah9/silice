FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y default-jre default-jdk git pkg-config uuid uuid-dev freeglut3 freeglut3-dev build-essential cmake

COPY . /repo
WORKDIR /repo
RUN ./compile_silice_linux.sh

WORKDIR /repo/tools/stl2raw/build
RUN cmake ..
RUN make -j8
FROM ubuntu:22.04 as package
COPY --from=builder /repo/tools/stl2raw/build/stl2raw /
