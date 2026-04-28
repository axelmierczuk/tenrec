/*
 * Fixture: "windows_debugger"
 *
 * Windows/PE variant of the debugger fixture, cross-compiled with
 * mingw-w64 in a Linux build stage and run inside a Windows Server Core
 * container under gdbserver.exe. The contract under test is identical
 * to the Linux variant: g_uninit_value lives in BSS (zero at startup),
 * update_value() writes 0xCAFEBABE through it.
 *
 * The MinGW-built PE doesn't depend on MSVC runtime — it links against
 * msvcrt which is present in every Windows base image, so the Windows
 * Server Core runtime image doesn't need extra runtime DLLs installed.
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
