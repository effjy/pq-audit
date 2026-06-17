/* segment.c — append-only segment format + hash chain, with rotation.
 * MIT (c) 2026 Jean-Francois Lachance-Caumartin
 *
 * On-disk layout (all integers little-endian):
 *
 *   header: magic[8] ver:u16 flags:u16 epoch:u64 seq0:u64 prev_root[32]   (60 B)
 *   entry : seq:u64 ts_real:u64 ts_mono:u64 src:u16 level:u8 plen:u32
 *           payload[plen] prev_hash[32] hash[32]
 *
 *   seed       = SHA256(DS ‖ ver ‖ flags ‖ epoch ‖ seq0 ‖ prev_root)
 *   entry.hash = SHA256(DS ‖ prev_hash ‖ seq ‖ ts_real ‖ ts_mono ‖ src ‖
 *                       level ‖ plen ‖ payload)
 *
 * A log is the ordered set of audit-NNNNNN.palog files.  Sequence numbers run
 * continuously across segments and the chain links across boundaries: each
 * segment's header.prev_segment_root carries the final head of the previous
 * segment, which is folded into this segment's seed.
 */
#define _POSIX_C_SOURCE 200809L
#include "pqaudit.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>

#define HEADER_LEN 60
#define ENTRY_FIXED_PRE  (8 + 8 + 8 + 2 + 1 + 4)  /* up to payload */

/* ---- little-endian helpers ---- */
static void put16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void put32(uint8_t *p, uint32_t v) { for (int i=0;i<4;i++) p[i]=(uint8_t)(v>>(8*i)); }
static void put64(uint8_t *p, uint64_t v) { for (int i=0;i<8;i++) p[i]=(uint8_t)(v>>(8*i)); }
static uint16_t get16(const uint8_t *p){ return (uint16_t)p[0]|((uint16_t)p[1]<<8); }
static uint32_t get32(const uint8_t *p){ uint32_t v=0; for(int i=0;i<4;i++) v|=(uint32_t)p[i]<<(8*i); return v; }
static uint64_t get64(const uint8_t *p){ uint64_t v=0; for(int i=0;i<8;i++) v|=(uint64_t)p[i]<<(8*i); return v; }

static int seg_file_path(char *buf, size_t n, const char *dir, unsigned idx)
{
    char name[64];
    snprintf(name, sizeof name, PQA_SEG_FMT, idx);
    return snprintf(buf, n, "%s/%s", dir, name) >= (int)n ? -1 : 0;
}

/* Collect segment indices present in `dir`, sorted ascending. Returns count
 * (>=0) into *n with a malloc'd array into *out (caller frees); -1 on error. */
static int list_segments(const char *dir, unsigned **out, int *n)
{
    DIR *d = opendir(dir);
    if (!d) { fprintf(stderr, "pq-audit: opendir %s: %s\n", dir, strerror(errno)); return -1; }
    unsigned *idx = NULL; int cnt = 0, cap = 0;
    struct dirent *e;
    size_t plen = strlen(PQA_SEG_PREFIX), slen = strlen(PQA_SEG_SUFFIX);
    while ((e = readdir(d))) {
        size_t L = strlen(e->d_name);
        if (L <= plen + slen) continue;
        if (strncmp(e->d_name, PQA_SEG_PREFIX, plen) != 0) continue;
        if (strcmp(e->d_name + L - slen, PQA_SEG_SUFFIX) != 0) continue;
        unsigned v;
        if (sscanf(e->d_name + plen, "%u", &v) != 1) continue;
        if (cnt == cap) { cap = cap ? cap*2 : 16; unsigned *p = realloc(idx, (size_t)cap*sizeof *p); if (!p) { free(idx); closedir(d); return -1; } idx = p; }
        idx[cnt++] = v;
    }
    closedir(d);
    /* insertion sort (segment counts are small) */
    for (int i = 1; i < cnt; i++) { unsigned k = idx[i]; int j = i-1; while (j>=0 && idx[j]>k) { idx[j+1]=idx[j]; j--; } idx[j+1]=k; }
    *out = idx; *n = cnt;
    return 0;
}

static int current_segment(const char *dir, unsigned *out_idx)
{
    unsigned *idx; int n;
    if (list_segments(dir, &idx, &n) != 0) return -1;
    if (n == 0) { free(idx); return -1; }
    *out_idx = idx[n-1];
    free(idx);
    return 0;
}

void pqa_header_seed(const pqa_seg_header *h, uint8_t out[PQA_HASH_LEN])
{
    uint8_t buf[2 + 2 + 8 + 8 + PQA_HASH_LEN];
    uint8_t *p = buf;
    put16(p, h->version); p += 2;
    put16(p, h->flags);   p += 2;
    put64(p, h->epoch);   p += 8;
    put64(p, h->seq0);    p += 8;
    memcpy(p, h->prev_segment_root, PQA_HASH_LEN); p += PQA_HASH_LEN;

    EVP_MD_CTX *c = EVP_MD_CTX_new();
    unsigned int ol = 0;
    EVP_DigestInit_ex(c, EVP_sha256(), NULL);
    EVP_DigestUpdate(c, PQA_DS_ENTRY, strlen(PQA_DS_ENTRY));
    EVP_DigestUpdate(c, buf, sizeof buf);
    EVP_DigestFinal_ex(c, out, &ol);
    EVP_MD_CTX_free(c);
}

static int entry_hash(const uint8_t prev_hash[PQA_HASH_LEN], uint64_t seq,
                      uint64_t tsr, uint64_t tsm, uint16_t src, uint8_t level,
                      uint32_t plen, const void *payload,
                      uint8_t out[PQA_HASH_LEN])
{
    uint8_t f[ENTRY_FIXED_PRE];
    uint8_t *p = f;
    put64(p, seq); p += 8;
    put64(p, tsr); p += 8;
    put64(p, tsm); p += 8;
    put16(p, src); p += 2;
    *p++ = level;
    put32(p, plen);

    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (!c) return -1;
    unsigned int ol = 0;
    int ok = EVP_DigestInit_ex(c, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(c, PQA_DS_ENTRY, strlen(PQA_DS_ENTRY)) == 1 &&
             EVP_DigestUpdate(c, prev_hash, PQA_HASH_LEN) == 1 &&
             EVP_DigestUpdate(c, f, sizeof f) == 1 &&
             (plen == 0 || EVP_DigestUpdate(c, payload, plen) == 1) &&
             EVP_DigestFinal_ex(c, out, &ol) == 1 && ol == PQA_HASH_LEN;
    EVP_MD_CTX_free(c);
    return ok ? 0 : -1;
}

static int read_full(FILE *f, void *buf, size_t n)
{
    return fread(buf, 1, n, f) == n ? 0 : -1;
}

static int read_header(FILE *f, pqa_seg_header *h)
{
    uint8_t buf[HEADER_LEN];
    if (read_full(f, buf, HEADER_LEN) != 0) return -1;
    if (memcmp(buf, PQA_MAGIC, PQA_MAGIC_LEN) != 0) return -1;
    h->version = get16(buf + 8);
    h->flags   = get16(buf + 10);
    h->epoch   = get64(buf + 12);
    h->seq0    = get64(buf + 20);
    memcpy(h->prev_segment_root, buf + 28, PQA_HASH_LEN);
    return h->version == PQA_VERSION ? 0 : -1;
}

typedef int (*pqa_entry_cb)(void *ctx, uint64_t seq, const uint8_t head[PQA_HASH_LEN]);

/* Verify one segment file's internal chain.  Fills *h_out, *out_count, and
 * out_final (= seed if empty); calls cb after each verified entry.  Sets
 * *cb_stop if cb asked to stop.  bad_seq optional. */
static int walk_one(const char *path, pqa_seg_header *h_out, uint64_t *out_count,
                    uint8_t out_final[PQA_HASH_LEN], uint64_t *bad_seq,
                    pqa_entry_cb cb, void *ctx, int *cb_stop)
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "pq-audit: open %s: %s\n", path, strerror(errno)); return PQA_EUSAGE; }
    pqa_seg_header h;
    if (read_header(f, &h) != 0) { fprintf(stderr, "pq-audit: bad header in %s\n", path); fclose(f); return PQA_ETAMPER; }
    if (h_out) *h_out = h;

    uint8_t prev[PQA_HASH_LEN];
    pqa_header_seed(&h, prev);
    uint64_t expect = h.seq0, count = 0;
    int rc = PQA_OK;

    for (;;) {
        uint8_t pre[ENTRY_FIXED_PRE];
        size_t got = fread(pre, 1, sizeof pre, f);
        if (got == 0 && feof(f)) break;
        if (got != sizeof pre) { if (bad_seq) *bad_seq = expect; rc = PQA_ETAMPER; goto done; }
        uint64_t seq  = get64(pre);
        uint64_t tsr  = get64(pre + 8);
        uint64_t tsm  = get64(pre + 16);
        uint16_t src  = get16(pre + 24);
        uint8_t  lvl  = pre[26];
        uint32_t plen = get32(pre + 27);

        uint8_t *payload = NULL;
        if (plen) {
            payload = malloc(plen);
            if (!payload) { rc = PQA_EUSAGE; goto done; }
            if (read_full(f, payload, plen) != 0) { free(payload); if (bad_seq) *bad_seq = seq; rc = PQA_ETAMPER; goto done; }
        }
        uint8_t rec_prev[PQA_HASH_LEN], rec_hash[PQA_HASH_LEN], calc[PQA_HASH_LEN];
        if (read_full(f, rec_prev, PQA_HASH_LEN) != 0 || read_full(f, rec_hash, PQA_HASH_LEN) != 0) {
            free(payload); if (bad_seq) *bad_seq = seq; rc = PQA_ETAMPER; goto done;
        }
        int bad = seq != expect ||
                  memcmp(rec_prev, prev, PQA_HASH_LEN) != 0 ||
                  entry_hash(prev, seq, tsr, tsm, src, lvl, plen, payload, calc) != 0 ||
                  memcmp(calc, rec_hash, PQA_HASH_LEN) != 0;
        free(payload);
        if (bad) { if (bad_seq) *bad_seq = seq; rc = PQA_ETAMPER; goto done; }
        memcpy(prev, rec_hash, PQA_HASH_LEN);
        expect = seq + 1;
        count++;
        if (cb && cb(ctx, seq, prev) != 0) { if (cb_stop) *cb_stop = 1; break; }
    }
    if (out_count) *out_count = count;
    if (out_final) memcpy(out_final, prev, PQA_HASH_LEN);
done:
    fclose(f);
    return rc;
}

/* Walk every segment in order, enforcing cross-segment continuity + linkage. */
static int walk_all(const char *dir, pqa_chain_state *out, uint64_t *bad_seq,
                    pqa_entry_cb cb, void *ctx)
{
    unsigned *idx; int n;
    if (list_segments(dir, &idx, &n) != 0) return PQA_EUSAGE;
    if (n == 0) { free(idx); fprintf(stderr, "pq-audit: no audit segments in %s\n", dir); return PQA_EUSAGE; }

    uint8_t prev_final[PQA_HASH_LEN];
    uint64_t expect_seq = 0, total = 0, first_epoch = 0;
    int rc = PQA_OK, stop = 0;

    for (int i = 0; i < n && !stop; i++) {
        char path[4096];
        if (seg_file_path(path, sizeof path, dir, idx[i]) != 0) { rc = PQA_EUSAGE; break; }
        pqa_seg_header h; uint64_t cnt = 0; uint8_t final[PQA_HASH_LEN];
        rc = walk_one(path, &h, &cnt, final, bad_seq, cb, ctx, &stop);
        if (rc != PQA_OK) break;

        if (i == 0) {
            first_epoch = h.epoch;
            uint8_t zero[PQA_HASH_LEN]; memset(zero, 0, sizeof zero);
            if (h.seq0 != 0 || memcmp(h.prev_segment_root, zero, PQA_HASH_LEN) != 0) {
                fprintf(stderr, "pq-audit: first segment must start at seq 0 with no prev root\n");
                if (bad_seq) *bad_seq = h.seq0;
                rc = PQA_ETAMPER; break;
            }
        } else {
            if (h.seq0 != expect_seq) {
                fprintf(stderr, "pq-audit: segment %u seq gap (have %llu, expected %llu)\n",
                        idx[i], (unsigned long long)h.seq0, (unsigned long long)expect_seq);
                if (bad_seq) *bad_seq = expect_seq;
                rc = PQA_ETAMPER; break;
            }
            if (memcmp(h.prev_segment_root, prev_final, PQA_HASH_LEN) != 0) {
                fprintf(stderr, "pq-audit: segment %u not linked to previous segment\n", idx[i]);
                if (bad_seq) *bad_seq = h.seq0;
                rc = PQA_ETAMPER; break;
            }
        }
        memcpy(prev_final, final, PQA_HASH_LEN);
        expect_seq = h.seq0 + cnt;
        total += cnt;
    }
    free(idx);
    if (rc != PQA_OK) return rc;

    if (out) {
        out->count = total;
        out->last_seq = total ? expect_seq - 1 : UINT64_MAX;
        out->epoch = first_epoch;
        memcpy(out->head_hash, prev_final, PQA_HASH_LEN);
    }
    return PQA_OK;
}

int pqa_segment_init(const char *dir, uint16_t flags, uint64_t epoch,
                     const uint8_t prev_segment_root[PQA_HASH_LEN])
{
    unsigned *idx; int n;
    if (list_segments(dir, &idx, &n) == 0) { free(idx); if (n > 0) { fprintf(stderr, "pq-audit: segments already exist in %s\n", dir); return PQA_EUSAGE; } }

    uint8_t buf[HEADER_LEN];
    memset(buf, 0, sizeof buf);
    memcpy(buf, PQA_MAGIC, PQA_MAGIC_LEN);
    put16(buf + 8,  PQA_VERSION);
    put16(buf + 10, flags);
    put64(buf + 12, epoch);
    put64(buf + 20, 0);                       /* seq0 of segment 0 */
    if (prev_segment_root) memcpy(buf + 28, prev_segment_root, PQA_HASH_LEN);

    char path[4096];
    if (seg_file_path(path, sizeof path, dir, 0) != 0) return PQA_EUSAGE;
    return pqa_write_atomic(path, buf, sizeof buf, 0600) == 0 ? PQA_OK : PQA_EUSAGE;
}

int pqa_segment_verify(const char *dir, pqa_chain_state *out, uint64_t *bad_seq)
{
    return walk_all(dir, out, bad_seq, NULL, NULL);
}

struct collect_ctx {
    uint64_t upto;
    uint8_t (*hashes)[PQA_HASH_LEN];
    uint64_t n, cap;
    int oom;
};
static int collect_cb(void *ctx, uint64_t seq, const uint8_t head[PQA_HASH_LEN])
{
    struct collect_ctx *c = ctx;
    if (c->n == c->cap) {
        uint64_t nc = c->cap ? c->cap * 2 : 64;
        void *p = realloc(c->hashes, nc * PQA_HASH_LEN);
        if (!p) { c->oom = 1; return 1; }
        c->hashes = p; c->cap = nc;
    }
    memcpy(c->hashes[c->n++], head, PQA_HASH_LEN);
    return (c->upto != UINT64_MAX && seq >= c->upto) ? 1 : 0;
}

int pqa_segment_collect(const char *dir, uint64_t upto,
                        uint8_t (**out_hashes)[PQA_HASH_LEN], uint64_t *out_n)
{
    struct collect_ctx c = { upto, NULL, 0, 0, 0 };
    int rc = walk_all(dir, NULL, NULL, collect_cb, &c);
    if (rc != PQA_OK) { free(c.hashes); return rc; }
    if (c.oom) { free(c.hashes); return PQA_EUSAGE; }
    if (upto != UINT64_MAX && c.n <= upto) {
        free(c.hashes);
        fprintf(stderr, "pq-audit: seq %llu beyond end of log\n", (unsigned long long)upto);
        return PQA_EUSAGE;
    }
    *out_hashes = c.hashes;
    *out_n = c.n;
    return PQA_OK;
}

struct head_at_ctx { uint64_t target; uint8_t head[PQA_HASH_LEN]; int found; };
static int head_at_cb(void *ctx, uint64_t seq, const uint8_t head[PQA_HASH_LEN])
{
    struct head_at_ctx *c = ctx;
    if (seq == c->target) { memcpy(c->head, head, PQA_HASH_LEN); c->found = 1; return 1; }
    return 0;
}

int pqa_segment_head_at(const char *dir, uint64_t target_seq,
                        uint8_t out_head[PQA_HASH_LEN])
{
    if (target_seq == UINT64_MAX) {
        pqa_chain_state st;
        int rc = walk_all(dir, &st, NULL, NULL, NULL);
        if (rc == PQA_OK) memcpy(out_head, st.head_hash, PQA_HASH_LEN);
        return rc;
    }
    struct head_at_ctx c = { target_seq, {0}, 0 };
    int rc = walk_all(dir, NULL, NULL, head_at_cb, &c);
    if (rc != PQA_OK) return rc;
    if (!c.found) { fprintf(stderr, "pq-audit: seq %llu beyond end of log\n", (unsigned long long)target_seq); return PQA_EUSAGE; }
    memcpy(out_head, c.head, PQA_HASH_LEN);
    return PQA_OK;
}

/* Active-segment state: walk only the highest-index segment (its seed encodes
 * all prior history via prev_segment_root), so append/rotate stay O(active). */
static int active_state(const char *dir, unsigned *idx, pqa_seg_header *h,
                        uint64_t *count, uint8_t final[PQA_HASH_LEN])
{
    if (current_segment(dir, idx) != 0) { fprintf(stderr, "pq-audit: no segments in %s (run init)\n", dir); return PQA_EUSAGE; }
    char path[4096];
    if (seg_file_path(path, sizeof path, dir, *idx) != 0) return PQA_EUSAGE;
    int stop = 0;
    return walk_one(path, h, count, final, NULL, NULL, NULL, &stop);
}

int pqa_segment_active_count(const char *dir, uint64_t *out)
{
    unsigned idx; pqa_seg_header h; uint64_t cnt; uint8_t final[PQA_HASH_LEN];
    int rc = active_state(dir, &idx, &h, &cnt, final);
    if (rc == PQA_OK) *out = cnt;
    return rc;
}

int pqa_segment_append(const char *dir, uint16_t src_id, uint8_t level,
                       const void *payload, uint32_t payload_len,
                       uint64_t *out_seq, uint8_t out_head[PQA_HASH_LEN])
{
    unsigned idx; pqa_seg_header h; uint64_t cnt; uint8_t head[PQA_HASH_LEN];
    int rc = active_state(dir, &idx, &h, &cnt, head);
    if (rc == PQA_ETAMPER) { fprintf(stderr, "pq-audit: refusing to append — active segment chain broken\n"); return PQA_ETAMPER; }
    if (rc != PQA_OK) return rc;

    uint64_t seq = h.seq0 + cnt;
    uint64_t tsr = pqa_now_realtime_ns();
    uint64_t tsm = pqa_now_mono_ns();
    uint8_t hash[PQA_HASH_LEN];
    if (entry_hash(head, seq, tsr, tsm, src_id, level, payload_len, payload, hash) != 0) return PQA_EUSAGE;

    size_t rec_len = ENTRY_FIXED_PRE + payload_len + 2 * PQA_HASH_LEN;
    uint8_t *rec = malloc(rec_len);
    if (!rec) return PQA_EUSAGE;
    uint8_t *p = rec;
    put64(p, seq); p += 8;
    put64(p, tsr); p += 8;
    put64(p, tsm); p += 8;
    put16(p, src_id); p += 2;
    *p++ = level;
    put32(p, payload_len); p += 4;
    if (payload_len) { memcpy(p, payload, payload_len); p += payload_len; }
    memcpy(p, head, PQA_HASH_LEN); p += PQA_HASH_LEN;
    memcpy(p, hash, PQA_HASH_LEN); p += PQA_HASH_LEN;

    char path[4096];
    if (seg_file_path(path, sizeof path, dir, idx) != 0) { free(rec); return PQA_EUSAGE; }
    int fd = open(path, O_WRONLY | O_APPEND);
    if (fd < 0) { free(rec); fprintf(stderr, "pq-audit: open %s: %s\n", path, strerror(errno)); return PQA_EUSAGE; }
    size_t off = 0;
    while (off < rec_len) { ssize_t w = write(fd, rec + off, rec_len - off); if (w < 0) { close(fd); free(rec); return PQA_EUSAGE; } off += (size_t)w; }
    int ok = fsync(fd) == 0;
    close(fd); free(rec);
    if (!ok) return PQA_EUSAGE;

    if (out_seq) *out_seq = seq;
    if (out_head) memcpy(out_head, hash, PQA_HASH_LEN);
    return PQA_OK;
}

int pqa_segment_rotate(const char *dir, unsigned *out_new_idx)
{
    unsigned idx; pqa_seg_header h; uint64_t cnt; uint8_t final[PQA_HASH_LEN];
    int rc = active_state(dir, &idx, &h, &cnt, final);
    if (rc != PQA_OK) return rc;
    if (cnt == 0) { fprintf(stderr, "pq-audit: active segment is empty — nothing to rotate\n"); return PQA_EUSAGE; }

    uint64_t next_seq0 = h.seq0 + cnt;
    uint8_t buf[HEADER_LEN];
    memset(buf, 0, sizeof buf);
    memcpy(buf, PQA_MAGIC, PQA_MAGIC_LEN);
    put16(buf + 8,  PQA_VERSION);
    put16(buf + 10, h.flags);
    put64(buf + 12, h.epoch);
    put64(buf + 20, next_seq0);
    memcpy(buf + 28, final, PQA_HASH_LEN);    /* link to prior segment's head */

    char path[4096];
    if (seg_file_path(path, sizeof path, dir, idx + 1) != 0) return PQA_EUSAGE;
    if (pqa_write_atomic(path, buf, sizeof buf, 0600) != 0) return PQA_EUSAGE;
    if (out_new_idx) *out_new_idx = idx + 1;
    return PQA_OK;
}
