/* merkle.c — Merkle tree + inclusion proofs (M4).
 * MIT (c) 2026 Jean-Francois Lachance-Caumartin
 *
 * Leaves are entry chain-hashes.  Domain separation is CT-style:
 *   leaf(h)        = SHA256(0x00 ‖ h)
 *   node(l, r)     = SHA256(0x01 ‖ l ‖ r)
 * Odd levels promote the unpaired node unchanged (RFC 6962 style).
 *
 * Proof blob (little-endian) read/written on stdin/stdout:
 *   magic "PQAPROOF" ver:u16 covers:u64 index:u64 leaf[32] depth:u32
 *   then depth × ( side:u8 ‖ sibling[32] )   side: 0=sibling-left, 1=sibling-right
 */
#define _POSIX_C_SOURCE 200809L
#include "pqaudit.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROOF_MAGIC "PQAPROOF"

static void hash_leaf(const uint8_t h[PQA_HASH_LEN], uint8_t out[PQA_HASH_LEN])
{
    uint8_t b[1 + PQA_HASH_LEN];
    b[0] = PQA_MT_LEAF;
    memcpy(b + 1, h, PQA_HASH_LEN);
    pqa_sha256(b, sizeof b, out);
}
static void hash_node(const uint8_t l[PQA_HASH_LEN], const uint8_t r[PQA_HASH_LEN],
                      uint8_t out[PQA_HASH_LEN])
{
    uint8_t b[1 + 2 * PQA_HASH_LEN];
    b[0] = PQA_MT_NODE;
    memcpy(b + 1, l, PQA_HASH_LEN);
    memcpy(b + 1 + PQA_HASH_LEN, r, PQA_HASH_LEN);
    pqa_sha256(b, sizeof b, out);
}

void pqa_merkle_root(const uint8_t (*leaves)[PQA_HASH_LEN], uint64_t n,
                     uint8_t out_root[PQA_HASH_LEN])
{
    if (n == 0) { memset(out_root, 0, PQA_HASH_LEN); return; }
    uint8_t (*lvl)[PQA_HASH_LEN] = malloc(n * PQA_HASH_LEN);
    if (!lvl) { memset(out_root, 0, PQA_HASH_LEN); return; }
    for (uint64_t i = 0; i < n; i++) hash_leaf(leaves[i], lvl[i]);

    uint64_t cnt = n;
    while (cnt > 1) {
        uint64_t w = 0;
        for (uint64_t i = 0; i < cnt; i += 2) {
            if (i + 1 < cnt) hash_node(lvl[i], lvl[i + 1], lvl[w]);
            else             memcpy(lvl[w], lvl[i], PQA_HASH_LEN); /* promote */
            w++;
        }
        cnt = w;
    }
    memcpy(out_root, lvl[0], PQA_HASH_LEN);
    free(lvl);
}

/* little-endian helpers */
static void put16(uint8_t *p, uint16_t v){ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void put32(uint8_t *p, uint32_t v){ for(int i=0;i<4;i++) p[i]=(uint8_t)(v>>(8*i)); }
static void put64(uint8_t *p, uint64_t v){ for(int i=0;i<8;i++) p[i]=(uint8_t)(v>>(8*i)); }
static uint16_t get16(const uint8_t *p){ return (uint16_t)p[0]|((uint16_t)p[1]<<8); }
static uint32_t get32(const uint8_t *p){ uint32_t v=0; for(int i=0;i<4;i++) v|=(uint32_t)p[i]<<(8*i); return v; }
static uint64_t get64(const uint8_t *p){ uint64_t v=0; for(int i=0;i<8;i++) v|=(uint64_t)p[i]<<(8*i); return v; }

/* Read the latest seal's covers_upto and its merkle_root. (Independent of
 * seal.c's static layout — we re-derive covers from the chain instead and
 * just trust the proof verifier to compare against a root from a verified
 * seal.)  Here we build the proof over [0..last_seq] of the whole log. */
int pqa_proof_emit(const char *dir, uint64_t seq)
{
    uint8_t (*leaves)[PQA_HASH_LEN] = NULL;
    uint64_t n = 0;
    int rc = pqa_segment_collect(dir, UINT64_MAX, &leaves, &n);
    if (rc != PQA_OK) return rc;
    if (seq >= n) {
        fprintf(stderr, "pq-audit: seq %llu beyond end of log (%llu entries)\n",
                (unsigned long long)seq, (unsigned long long)n);
        free(leaves); return PQA_EUSAGE;
    }

    /* collect the audit path while folding the tree */
    uint8_t (*lvl)[PQA_HASH_LEN] = malloc(n * PQA_HASH_LEN);
    if (!lvl) { free(leaves); return PQA_EUSAGE; }
    for (uint64_t i = 0; i < n; i++) hash_leaf(leaves[i], lvl[i]);

    uint8_t leaf_entry[PQA_HASH_LEN];
    memcpy(leaf_entry, leaves[seq], PQA_HASH_LEN);
    free(leaves);

    /* path buffers */
    uint8_t (*sib)[PQA_HASH_LEN] = malloc(n * PQA_HASH_LEN);  /* >= depth */
    uint8_t *side = malloc(n ? n : 1);
    if (!sib || !side) { free(lvl); free(sib); free(side); return PQA_EUSAGE; }
    uint32_t depth = 0;
    uint64_t idx = seq, cnt = n;
    while (cnt > 1) {
        uint64_t pair = (idx % 2 == 0) ? idx + 1 : idx - 1;
        if (idx % 2 == 0 && pair >= cnt) {
            /* promoted (no sibling): nothing added to the path */
        } else {
            memcpy(sib[depth], lvl[pair], PQA_HASH_LEN);
            side[depth] = (idx % 2 == 0) ? 1 : 0; /* sibling on the right? */
            depth++;
        }
        /* fold this level */
        uint64_t w = 0;
        for (uint64_t i = 0; i < cnt; i += 2) {
            if (i + 1 < cnt) hash_node(lvl[i], lvl[i + 1], lvl[w]);
            else             memcpy(lvl[w], lvl[i], PQA_HASH_LEN);
            w++;
        }
        cnt = w;
        idx /= 2;
    }
    free(lvl);

    size_t blen = 8 + 2 + 8 + 8 + PQA_HASH_LEN + 4 + (size_t)depth * (1 + PQA_HASH_LEN);
    uint8_t *blob = malloc(blen);
    if (!blob) { free(sib); free(side); return PQA_EUSAGE; }
    uint8_t *p = blob;
    memcpy(p, PROOF_MAGIC, 8); p += 8;
    put16(p, PQA_VERSION); p += 2;
    put64(p, n - 1);   p += 8;          /* covers_upto = last seq */
    put64(p, seq);     p += 8;
    memcpy(p, leaf_entry, PQA_HASH_LEN); p += PQA_HASH_LEN;
    put32(p, depth);   p += 4;
    for (uint32_t i = 0; i < depth; i++) {
        *p++ = side[i];
        memcpy(p, sib[i], PQA_HASH_LEN); p += PQA_HASH_LEN;
    }
    free(sib); free(side);

    size_t off = 0;
    while (off < blen) {
        ssize_t w = write(STDOUT_FILENO, blob + off, blen - off);
        if (w < 0) { free(blob); return PQA_EUSAGE; }
        off += (size_t)w;
    }
    free(blob);
    return PQA_OK;
}

static int hex2bin(const char *hex, uint8_t *out, size_t n)
{
    if (strlen(hex) != 2 * n) return -1;
    for (size_t i = 0; i < n; i++) {
        int hi, lo;
        char a = hex[2*i], b = hex[2*i+1];
        hi = (a>='0'&&a<='9')?a-'0':(a>='a'&&a<='f')?a-'a'+10:(a>='A'&&a<='F')?a-'A'+10:-1;
        lo = (b>='0'&&b<='9')?b-'0':(b>='a'&&b<='f')?b-'a'+10:(b>='A'&&b<='F')?b-'A'+10:-1;
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

int pqa_proof_check(const char *root_hex)
{
    uint8_t want[PQA_HASH_LEN];
    if (!root_hex || hex2bin(root_hex, want, PQA_HASH_LEN) != 0) {
        fprintf(stderr, "pq-audit: --root must be %d hex bytes\n", PQA_HASH_LEN);
        return PQA_EUSAGE;
    }
    /* slurp stdin */
    size_t cap = 8192, len = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) return PQA_EUSAGE;
    for (;;) {
        if (len == cap) { cap *= 2; uint8_t *nb = realloc(buf, cap); if (!nb) { free(buf); return PQA_EUSAGE; } buf = nb; }
        ssize_t r = read(STDIN_FILENO, buf + len, cap - len);
        if (r < 0) { free(buf); return PQA_EUSAGE; }
        if (r == 0) break;
        len += (size_t)r;
    }
    const size_t fixed = 8 + 2 + 8 + 8 + PQA_HASH_LEN + 4;
    if (len < fixed || memcmp(buf, PROOF_MAGIC, 8) != 0 || get16(buf + 8) != PQA_VERSION) {
        fprintf(stderr, "pq-audit: malformed proof\n"); free(buf); return PQA_EUSAGE;
    }
    uint64_t seq = get64(buf + 18);
    const uint8_t *leaf = buf + 26;
    uint32_t depth = get32(buf + 26 + PQA_HASH_LEN);
    if (len != fixed + (size_t)depth * (1 + PQA_HASH_LEN)) {
        fprintf(stderr, "pq-audit: malformed proof (length)\n"); free(buf); return PQA_EUSAGE;
    }

    uint8_t acc[PQA_HASH_LEN];
    hash_leaf(leaf, acc);
    const uint8_t *p = buf + fixed;
    for (uint32_t i = 0; i < depth; i++) {
        uint8_t side = *p++;
        const uint8_t *sib = p; p += PQA_HASH_LEN;
        uint8_t nh[PQA_HASH_LEN];
        if (side == 1) hash_node(acc, sib, nh);   /* sibling on the right */
        else           hash_node(sib, acc, nh);   /* sibling on the left  */
        memcpy(acc, nh, PQA_HASH_LEN);
    }
    free(buf);

    int ok = memcmp(acc, want, PQA_HASH_LEN) == 0;
    if (ok) printf("PROOF OK: entry %llu is in the sealed log\n", (unsigned long long)seq);
    else    printf("PROOF FAILED: entry does not match the given root\n");
    return ok ? PQA_OK : PQA_ETAMPER;
}
