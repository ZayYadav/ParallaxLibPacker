#pragma once

/*
 * Parallax PVM4 transport virtualization.
 *
 * This is a reversible diversification layer for compressed Android ARM64
 * shared-library blocks. It is intentionally freestanding so the exact same
 * implementation is compiled into the packer and the tiny runtime ELF-SO stub.
 *
 * Security role:
 *   - removes standard compressed-block bytes from the on-disk artifact;
 *   - creates four execution-order dialects ("lanes") selected per block;
 *   - uses a per-file program id plus per-block tag for diversification;
 *   - decodes only the block currently being consumed by the runtime loader.
 *
 * It is NOT a cryptographic primitive and does not replace authenticated
 * encryption or full native-instruction virtualization.
 */

#ifndef PARALLAX_VM4_MARKER
#  define PARALLAX_VM4_MARKER      0xA0u
#  define PARALLAX_VM4_MARKER_MASK 0xF0u
#  define PARALLAX_VM4_LANE_MASK   0x03u
#endif

static inline unsigned parallax_vm4_rotl32(unsigned x, unsigned r) {
    r &= 31u;
    return r ? ((x << r) | (x >> (32u - r))) : x;
}

static inline unsigned char parallax_vm4_rotl8(unsigned char x, unsigned r) {
    r &= 7u;
    return r ? (unsigned char)((x << r) | (x >> (8u - r))) : x;
}

static inline unsigned char parallax_vm4_rotr8(unsigned char x, unsigned r) {
    r &= 7u;
    return r ? (unsigned char)((x >> r) | (x << (8u - r))) : x;
}

static inline unsigned parallax_vm4_mix32(unsigned x) {
    x ^= x >> 16;
    x *= 0x7feb352du;
    x ^= x >> 15;
    x *= 0x846ca68bu;
    x ^= x >> 16;
    return x ? x : 0x6d2b79f5u;
}

static inline unsigned parallax_vm4_seed(
        unsigned program_id,
        unsigned unc_len,
        unsigned cpr_len,
        unsigned method,
        unsigned tag) {
    unsigned x = program_id ^ 0x504d5634u; /* "PMV4" domain separator */
    x ^= parallax_vm4_rotl32(unc_len, 7);
    x ^= parallax_vm4_rotl32(cpr_len, 17);
    x ^= (method & 0xffu) << 24;
    x ^= (tag & 0xffu) * 0x9e3779b9u;
    return parallax_vm4_mix32(x);
}

static inline unsigned parallax_vm4_next(unsigned *state) {
    unsigned x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static inline void parallax_vm4_stage_stream_xor(
        unsigned char *data, size_t len, unsigned seed) {
    unsigned state = seed ^ 0x243f6a88u;
    size_t i;
    for (i = 0; i < len; ++i) {
        unsigned x = parallax_vm4_next(&state);
        unsigned shift = (unsigned)(i & 3u) * 8u;
        data[i] ^= (unsigned char)((x >> shift) & 0xffu);
    }
}

static inline void parallax_vm4_stage_add(
        unsigned char *data, size_t len, unsigned seed, unsigned tag, int inverse) {
    size_t i;
    for (i = 0; i < len; ++i) {
        unsigned shift = (unsigned)(i & 3u) * 8u;
        unsigned k = ((seed >> shift) & 0xffu)
                ^ ((unsigned)(i * 29u + tag * 17u) & 0xffu);
        data[i] = inverse
                ? (unsigned char)(data[i] - (unsigned char)k)
                : (unsigned char)(data[i] + (unsigned char)k);
    }
}

static inline void parallax_vm4_stage_rotate(
        unsigned char *data, size_t len, unsigned seed, unsigned tag, int inverse) {
    size_t i;
    for (i = 0; i < len; ++i) {
        unsigned r = 1u + ((seed ^ (unsigned)(i * 7u) ^ tag) % 7u);
        data[i] = inverse
                ? parallax_vm4_rotr8(data[i], r)
                : parallax_vm4_rotl8(data[i], r);
    }
}

static inline void parallax_vm4_stage_permute(
        unsigned char *data, size_t len, unsigned seed) {
    const size_t width = (size_t)(8u + ((seed >> 8) & 7u));
    size_t base;
    for (base = 0; base < len; base += width) {
        size_t lo = base;
        size_t hi = base + width;
        if (hi > len)
            hi = len;
        while (lo + 1u < hi) {
            unsigned char t;
            --hi;
            t = data[lo];
            data[lo] = data[hi];
            data[hi] = t;
            ++lo;
        }
    }
}

static inline void parallax_vm4_stage(
        unsigned stage,
        unsigned char *data,
        size_t len,
        unsigned seed,
        unsigned tag,
        int inverse) {
    switch (stage & 3u) {
    case 0:
        parallax_vm4_stage_stream_xor(data, len, seed ^ 0x13198a2eu);
        break;
    case 1:
        parallax_vm4_stage_add(data, len, seed ^ 0xa4093822u, tag, inverse);
        break;
    case 2:
        parallax_vm4_stage_rotate(data, len, seed ^ 0x299f31d0u, tag, inverse);
        break;
    default:
        parallax_vm4_stage_permute(data, len, seed ^ 0x082efa98u);
        break;
    }
}

static inline unsigned parallax_vm4_order(unsigned lane, unsigned index) {
    unsigned packed;
    lane &= PARALLAX_VM4_LANE_MASK;
    index &= 3u;
    if (lane == 0u)
        packed = 0x03020100u;
    else if (lane == 1u)
        packed = 0x02000301u;
    else if (lane == 2u)
        packed = 0x01030002u;
    else
        packed = 0x00010203u;
    return (packed >> (index * 8u)) & 0xffu;
}

static inline void parallax_vm4_encode(
        unsigned char *data,
        size_t len,
        unsigned program_id,
        unsigned unc_len,
        unsigned cpr_len,
        unsigned method,
        unsigned tag) {
    unsigned seed = parallax_vm4_seed(program_id, unc_len, cpr_len, method, tag);
    unsigned lane = tag & PARALLAX_VM4_LANE_MASK;
    unsigned i;
    for (i = 0; i < 4u; ++i) {
        parallax_vm4_stage(
                parallax_vm4_order(lane, i), data, len, seed, tag, 0);
    }
}

static inline void parallax_vm4_decode(
        unsigned char *data,
        size_t len,
        unsigned program_id,
        unsigned unc_len,
        unsigned cpr_len,
        unsigned method,
        unsigned tag) {
    unsigned seed = parallax_vm4_seed(program_id, unc_len, cpr_len, method, tag);
    unsigned lane = tag & PARALLAX_VM4_LANE_MASK;
    unsigned i = 4u;
    while (i != 0u) {
        --i;
        parallax_vm4_stage(
                parallax_vm4_order(lane, i), data, len, seed, tag, 1);
    }
}

static inline int parallax_vm4_is_tag(unsigned tag) {
    return (tag & PARALLAX_VM4_MARKER_MASK) == PARALLAX_VM4_MARKER;
}
