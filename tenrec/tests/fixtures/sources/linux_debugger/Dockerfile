# Build a Linux ELF of the debugger fixture and bundle gdbserver to drive it.
#
# The image has two purposes that share the same layer set:
#   * Build artefact source: build_fixtures.py extracts /fixture/debugger
#     out of this image to feed ida-domain (host-side) for .i64 generation.
#   * Runtime target: integration tests run this image to spawn gdbserver,
#     pre-launching the binary in a stopped state for IDA's gdb-remote
#     backend to attach to.
#
# debian:stable-slim is small, has glibc, and ships gcc + gdbserver — no
# need to compile a custom toolchain. -no-pie keeps the load address
# easier to reason about in test assertions, though gdbserver handles PIE
# correctly either way.

FROM debian:stable-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev gdbserver && rm -rf /var/lib/apt/lists/*

WORKDIR /fixture
COPY debugger.c .

# -O0 -g preserves source-level structure so IDA's symbol lookup hits the
# expected names; -fno-omit-frame-pointer makes the prologue stable across
# gcc versions.
RUN gcc -O0 -g -fno-omit-frame-pointer -no-pie -o debugger debugger.c

EXPOSE 31337

# Default command: pre-launch the binary under gdbserver listening on
# 0.0.0.0:31337. The host (or another container) connects via the
# published port.
CMD ["gdbserver", "0.0.0.0:31337", "/fixture/debugger"]
