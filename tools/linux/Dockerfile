# The Linux build and headless image: the pinned toolchain (cmake/toolchains/linux-clang-pins.cmake)
# installed by tools/linux/toolchain.sh, with the client's headers.
#
#   docker build -t faf-linux:22.04 -f tools/linux/Dockerfile tools/linux
FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11
COPY toolchain.sh /tmp/toolchain.sh
RUN bash /tmp/toolchain.sh --client && rm -rf /var/lib/apt/lists/* /tmp/*
WORKDIR /home/dev/faf
