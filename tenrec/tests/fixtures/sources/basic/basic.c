/*
 * Fixture: "basic"
 *
 * Exercises a representative slice of every plugin surface so integration
 * tests can verify end-to-end behaviour against a real IDA database.
 *
 * Things deliberately included:
 *   - multiple user-defined functions with different signatures
 *   - one __attribute__((noreturn)) function (functions.does_return / FunctionFlags)
 *   - a small struct (types.get_at, types.get_by_name)
 *   - initialised and uninitialised globals (bytes, names, segments)
 *   - several string literals (strings)
 *   - imports of well-known libc symbols (imports)
 *   - direct call chains (xrefs.calls_to / get_xref_graph)
 *   - data references between functions and globals (xrefs.reads_of / writes_to)
 *
 * Keep this file short and intentional: every symbol here is a test
 * landmark.  When adding new behaviour, prefer a new fixture target over
 * piling more into "basic".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char g_greeting[] = "Hello, fixture";
const char g_label_origin[] = "origin";
int g_counter = 0;
int g_buffer[16];

struct Point {
    int x;
    int y;
    const char *label;
};

static struct Point g_origin = {0, 0, g_label_origin};

/* compute_sum is reachable only from main, used to validate xrefs/callers. */
static int compute_sum(int a, int b) {
    int result = a + b;
    g_counter += result;
    return result;
}

/* Noreturn so functions.does_return == False and FunctionFlags.NORET is set. */
__attribute__((noreturn))
static void fatal_error(const char *msg) {
    printf("FATAL: %s\n", msg);
    exit(1);
}

/* Multiple locals + struct usage to exercise get_local_variables and types. */
int process_buffer(int *buf, int n) {
    int min = buf[0];
    int max = buf[0];
    int sum = 0;
    for (int i = 0; i < n; i++) {
        if (buf[i] < min) min = buf[i];
        if (buf[i] > max) max = buf[i];
        sum += buf[i];
    }
    return max - min + sum;
}

int main(int argc, char **argv) {
    (void)argv;
    printf("%s\n", g_greeting);
    int s = compute_sum(argc, 42);
    g_origin.x = s;
    g_origin.y = (int)strlen(g_greeting);
    if (argc > 99) {
        fatal_error("too many args");
    }
    return process_buffer(g_buffer, 16);
}
