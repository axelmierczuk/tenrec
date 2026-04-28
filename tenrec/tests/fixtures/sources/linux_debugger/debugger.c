/*
 * Fixture: "linux_debugger"
 *
 * Linux/ELF variant of the debugger fixture, built and run inside a
 * Docker container. The contract under test is identical to the macOS
 * variant: g_uninit_value lives in BSS (so it must read as zero at
 * process start) and update_value() writes 0xCAFEBABE through it. With
 * the test stopped at update_value's entry, runtime memory must show
 * zeros; after stepping past the assignment, it must show the signature.
 *
 * Why a separate file from sources/debugger/debugger.c: the macOS
 * variant has a SIGSTOP self-suspend hook that's only useful when the
 * debugger needs a moment to attach. gdbserver pre-launches the target
 * stopped at entry by default, so that hook is unnecessary on Linux —
 * keeping it out of the Linux build avoids loading a libc whose signal
 * semantics differ between glibc and the macOS C runtime.
 */

#include <stdio.h>

volatile unsigned int g_uninit_value;  /* BSS — zero at process start */

void update_value(unsigned int new_value) {
    g_uninit_value = new_value;
}

unsigned int read_value(void) {
    return g_uninit_value;
}

int main(void) {
    unsigned int before = read_value();
    printf("before=0x%x\n", before);

    update_value(0xCAFEBABE);

    unsigned int after = read_value();
    printf("after=0x%x\n", after);

    return (before == 0u && after == 0xCAFEBABEu) ? 0 : 1;
}
