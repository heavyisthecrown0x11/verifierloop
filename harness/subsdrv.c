/* subsdrv — run bpfsubs.h over a capture file and print its aggregates.
 *
 * This exists for ONE reason: `bpfsubs.h` is a second implementation of a predicate that
 * `scripts/subsume-check.py` already implements, and a second implementation is only worth
 * its cost while the two are provably the same. This driver is what makes that provable
 * from the test suite instead of by hand — see crates/pipeline/tests/subsumption_model.rs.
 *
 * The Python model stays the REFERENCE: it is the one calibrated against real kernel bugs.
 * This one is calibrated against it.
 */
#include <stdlib.h>
#include <stdio.h>
#include "bpfsubs.h"
int main(int argc, char **argv) {
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 2;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)n + 1);
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) return 2;
    buf[n] = 0; fclose(f);
    struct bpfsubs_cmp c;
    bpfsubs_compare_log(buf, &c);
    printf("pairs=%lu agree=%lu disagree=%lu unmodelled=%lu nontrivial=%lu "
           "scalar=%lu ptr=%lu sc=%lu unsup=%lu rows=%lu first=%s\n",
           c.pairs, c.agree, c.disagree, c.unmodelled, c.nontrivial,
           c.scalar_cmp, c.ptr_cmp, c.shortcircuit, c.unsupported, c.rows,
           c.first[0] ? c.first : "-");
    return 0;
}
