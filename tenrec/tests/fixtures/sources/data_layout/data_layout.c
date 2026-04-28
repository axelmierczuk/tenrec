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
 *
 * The float/double/oword/yword globals exist so the bytes plugin can be
 * asked to apply those data-type definitions to known addresses. IDA does
 * not always auto-classify wider numeric types — the integration tests
 * drive the plugin contract by calling create_data_at(...) explicitly.
 */

#include <stdint.h>

const uint8_t  g_bytes[8]  = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
const uint16_t g_words[4]  = {0x1100u, 0x2200u, 0x3300u, 0x4400u};
const uint32_t g_dwords[2] = {0xCAFEBABEu, 0xDEADBEEFu};
const uint64_t g_qword     = 0x1234567890ABCDEFULL;
const char     g_marker[]  = "data_layout_marker";

const float  g_floats[2]  = {3.14f, 2.71828f};
const double g_doubles[2] = {3.141592653589793, 2.718281828459045};

/* 16- and 32-byte aligned regions for oword/yword type application. */
const uint8_t __attribute__((aligned(16))) g_oword[16] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};
const uint8_t __attribute__((aligned(32))) g_yword[32] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
};

/* volatile sinks force the linker to preserve every referenced global. */
volatile uint32_t g_sink;
volatile float    g_float_sink;
volatile double   g_double_sink;
volatile uint8_t  g_wide_sink;

int main(void) {
    g_sink ^= g_dwords[0];
    g_sink ^= g_dwords[1];
    g_sink ^= (uint32_t)g_qword;
    g_sink ^= g_bytes[0];
    g_sink ^= g_words[0];
    g_float_sink  = g_floats[0] + g_floats[1];
    g_double_sink = g_doubles[0] - g_doubles[1];
    g_wide_sink   = g_oword[0] ^ g_yword[0];
    return (int)g_sink + g_marker[0];
}
