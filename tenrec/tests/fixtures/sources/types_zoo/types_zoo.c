/*
 * Fixture: "types_zoo"
 *
 * Provides stable addresses to attach types to, plus a few enums, unions,
 * structs, typedefs and a function pointer so the types plugin has a
 * realistic surface to work against. Tests should drive the types plugin
 * round-trip (declare -> apply -> get_at -> list_local_types) rather than
 * relying on whatever IDA infers from the binary by itself.
 */

#include <stdint.h>
#include <stdio.h>

enum Color {
    COLOR_RED   = 1,
    COLOR_GREEN = 2,
    COLOR_BLUE  = 4,
};

struct config_t {
    int width;
    int height;
    enum Color background;
};

union word_t {
    uint32_t as_int;
    uint8_t  bytes[4];
};

typedef int (*op_fn)(int, int);

/* Initialised globals — guaranteed to land in .data with stable symbol names. */
struct config_t g_config = {1024, 768, COLOR_RED};
union word_t g_word = {.as_int = 0xCAFEBABEu};

/* Two operations + an indirect-call dispatcher exercise xref/types overlap. */
static int op_add(int a, int b) { return a + b; }
static int op_sub(int a, int b) { return a - b; }

static int apply_op(op_fn op, int a, int b) {
    return op(a, b);
}

int main(int argc, char **argv) {
    (void)argv;
    op_fn op = (argc & 1) ? op_add : op_sub;
    int s = apply_op(op, g_config.width, g_config.height);
    printf("%x %d %x\n", g_word.as_int, s, g_config.background);
    return s;
}
