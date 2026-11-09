# The dedicated server's image: one game per container, not root, with nothing but the program.
# The build context is the folder holding a built `server` (cmake --preset linux-clang-x64-release).
# Game data is mounted read-only and the output folder writable; docs/SWITCHES.md has the command.
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin faf
COPY server /opt/faf/server
USER 10001
WORKDIR /opt/faf
ENTRYPOINT ["/opt/faf/server"]
