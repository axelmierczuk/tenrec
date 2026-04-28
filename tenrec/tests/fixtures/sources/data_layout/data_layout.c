/*
 * Fixture: "data_layout"
 *
 * Hand-laid global data with predictable contents so the bytes plugin can be
 * exercised against real values. Every global is referenced from main() to
 * stop the linker from stripping them at -O0.
 *
 * Constants are byte-ordered intentionally:
 *   g_bytes  — eight bytes 01..08 (no endianness, stable across archs)
 *   g_dwords — 0xCAFEBABE, 0xDEADBEEF (little-endian on x86_64 / arm64)
 *   g_qword  — 0x1234567890ABCDEF
 *
 * The string g_marker is a unique signature that find_text_between can
 * locate without relying on any other symbol resolution.
 */

#include <stdint.h>

const uint8_t  g_bytes[8]  = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
const uint16_t g_words[4]  = {0x1100u, 0x2200u, 0x3300u, 0x4400u};
const uint32_t g_dwords[2] = {0xCAFEBABEu, 0xDEADBEEFu};
const uint64_t g_qword     = 0x1234567890ABCDEFULL;
const char     g_marker[]  = "data_layout_marker";

/* volatile sink keeps the linker honest about preserving the globals above. */
volatile uint32_t g_sink;

int main(void) {
    g_sink ^= g_dwords[0];
    g_sink ^= g_dwords[1];
    g_sink ^= (uint32_t)g_qword;
    g_sink ^= g_bytes[0];
    g_sink ^= g_words[0];
    return (int)g_sink + g_marker[0];
}
