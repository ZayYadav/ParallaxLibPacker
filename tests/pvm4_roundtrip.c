#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../upx-devel/src/parallax_vm4.h"

int main(void) {
    unsigned char original[4097];
    unsigned char work[4097];
    size_t i;
    unsigned tag;

    for (i = 0; i < sizeof(original); ++i)
        original[i] = (unsigned char)((i * 37u + (i >> 3) * 11u) & 0xffu);

    for (tag = 0xA0u; tag <= 0xAFu; ++tag) {
        memcpy(work, original, sizeof(work));
        parallax_vm4_encode(
                work, sizeof(work),
                0x7b21c04du,
                0x13579u,
                (unsigned)sizeof(work),
                0x2u,
                tag);

        if (memcmp(work, original, sizeof(work)) == 0) {
            fprintf(stderr, "PVM4 tag %#x produced identity transform\n", tag);
            return 1;
        }

        parallax_vm4_decode(
                work, sizeof(work),
                0x7b21c04du,
                0x13579u,
                (unsigned)sizeof(work),
                0x2u,
                tag);

        if (memcmp(work, original, sizeof(work)) != 0) {
            fprintf(stderr, "PVM4 round trip failed for tag %#x\n", tag);
            return 2;
        }
    }

    puts("PVM4 round-trip vectors: PASS");
    return 0;
}
