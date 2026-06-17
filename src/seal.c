/* seal.c — post-quantum sealing of the chain head + Merkle root (M2/M3/M4).
 * Reuses the vendored pq-sign library (key armor, PQSIGN container, liboqs glue).
 * MIT (c) 2026 Jean-Francois Lachance-Caumartin
 *
 * audit.seal layout (little-endian):
 *   header: magic[8] ver:u16
 *   seal  : seal_seq:u64 covers:u64 key_epoch:u64 head[32] merkle_root[32]
 *           blob_len:u32 blob[blob_len]   (PQSIGN container)
 *
 *   signed digest = SHA256(DS_SEAL ‖ ver ‖ epoch ‖ covers ‖ key_epoch
 *                          ‖ head ‖ merkle_root)
 */
#define _POSIX_C_SOURCE 200809L
#include "fs_internal.h"
#include "seal_internal.h"
#include "pqoqs.h"
#include "pqsign.h"
#include "keyfile_internal.h"   /* vendored: key_armor_parse / key_decrypt */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SEAL_HDR_LEN  10
#define SEAL_FIXED    (8 + 8 + 8 + PQA_HASH_LEN + PQA_HASH_LEN + 4)

static void put16(uint8_t *p, uint16_t v){ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void put32(uint8_t *p, uint32_t v){ for(int i=0;i<4;i++) p[i]=(uint8_t)(v>>(8*i)); }
static void put64(uint8_t *p, uint64_t v){ for(int i=0;i<8;i++) p[i]=(uint8_t)(v>>(8*i)); }
static uint16_t get16(const uint8_t *p){ return (uint16_t)p[0]|((uint16_t)p[1]<<8); }
static uint32_t get32(const uint8_t *p){ uint32_t v=0; for(int i=0;i<4;i++) v|=(uint32_t)p[i]<<(8*i); return v; }
static uint64_t get64(const uint8_t *p){ uint64_t v=0; for(int i=0;i<8;i++) v|=(uint64_t)p[i]<<(8*i); return v; }

static int seal_path(char *buf, size_t n, const char *dir)
{
    return snprintf(buf, n, "%s/%s", dir, PQA_SEAL_FILE) >= (int)n ? -1 : 0;
}

static void seal_digest(uint64_t epoch, uint64_t covers, uint64_t key_epoch,
                        const uint8_t head[PQA_HASH_LEN],
                        const uint8_t mroot[PQA_HASH_LEN], uint8_t out[PQA_HASH_LEN])
{
    uint8_t buf[2 + 8 + 8 + 8 + PQA_HASH_LEN + PQA_HASH_LEN];
    uint8_t *p = buf;
    put16(p, PQA_VERSION); p += 2;
    put64(p, epoch);       p += 8;
    put64(p, covers);      p += 8;
    put64(p, key_epoch);   p += 8;
    memcpy(p, head, PQA_HASH_LEN);  p += PQA_HASH_LEN;
    memcpy(p, mroot, PQA_HASH_LEN);

    size_t dl = strlen(PQA_DS_SEAL);
    uint8_t pre[64 + sizeof buf];
    memcpy(pre, PQA_DS_SEAL, dl);
    memcpy(pre + dl, buf, sizeof buf);
    pqa_sha256(pre, dl + sizeof buf, out);
}

/* Merkle root over entries [0 .. covers]. */
static int merkle_for(const char *dir, uint64_t covers, uint8_t out[PQA_HASH_LEN])
{
    uint8_t (*leaves)[PQA_HASH_LEN] = NULL;
    uint64_t n = 0;
    int rc = pqa_segment_collect(dir, covers, &leaves, &n);
    if (rc != PQA_OK) return rc;
    pqa_merkle_root(leaves, covers + 1, out);
    free(leaves);
    return PQA_OK;
}

/* Append one fully-formed seal record to a seal-journal file, writing the
 * PQASEAL header first if the file is new.  Used for the primary audit.seal
 * and for every off-box sink (identical format → independently verifiable). */
static int append_seal_file(const char *path, const uint8_t *rec, size_t rec_len)
{
    int existed = access(path, F_OK) == 0;
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) { fprintf(stderr, "pq-audit: open %s: %s\n", path, strerror(errno)); return -1; }
    if (!existed) {
        uint8_t hdr[SEAL_HDR_LEN];
        memcpy(hdr, PQA_SEAL_MAGIC, 8); put16(hdr + 8, PQA_VERSION);
        if (write(fd, hdr, SEAL_HDR_LEN) != SEAL_HDR_LEN) { close(fd); return -1; }
    }
    int ok = (write(fd, rec, rec_len) == (ssize_t)rec_len) && fsync(fd) == 0;
    close(fd);
    return ok ? 0 : -1;
}

int pqa_seal_with_key(const char *dir, const pqsign_key *sk, uint64_t key_epoch,
                      int verbose, const char *const *sinks, int n_sinks)
{
    pqa_chain_state st;
    uint64_t bad = 0;
    int rc = pqa_segment_verify(dir, &st, &bad);
    if (rc == PQA_ETAMPER) {
        fprintf(stderr, "pq-audit: refusing to seal — chain broken at seq %llu\n",
                (unsigned long long)bad);
        return PQA_ETAMPER;
    }
    if (rc != PQA_OK) return rc;
    if (st.last_seq == UINT64_MAX) { fprintf(stderr, "pq-audit: nothing to seal (empty log)\n"); return PQA_EUSAGE; }

    uint8_t mroot[PQA_HASH_LEN];
    if (merkle_for(dir, st.last_seq, mroot) != PQA_OK) return PQA_EUSAGE;

    uint8_t digest[PQA_HASH_LEN];
    seal_digest(st.epoch, st.last_seq, key_epoch, st.head_hash, mroot, digest);
    size_t blob_len = 0;
    uint8_t *blob = pqoqs_sign_digest(sk, digest, &blob_len);
    if (!blob) return PQA_EUSAGE;

    size_t rec_len = SEAL_FIXED + blob_len;
    uint8_t *rec = malloc(rec_len), *p = rec;
    if (!rec) { free(blob); return PQA_EUSAGE; }
    put64(p, 0); p += 8;                       /* seal_seq: ordinal/implicit */
    put64(p, st.last_seq); p += 8;
    put64(p, key_epoch); p += 8;
    memcpy(p, st.head_hash, PQA_HASH_LEN); p += PQA_HASH_LEN;
    memcpy(p, mroot, PQA_HASH_LEN); p += PQA_HASH_LEN;
    put32(p, (uint32_t)blob_len); p += 4;
    memcpy(p, blob, blob_len);
    free(blob);

    char path[4096];
    if (seal_path(path, sizeof path, dir) != 0) { free(rec); return PQA_EUSAGE; }
    if (append_seal_file(path, rec, rec_len) != 0) { free(rec); return PQA_EUSAGE; }
    /* mirror to off-box sinks; a sink failure is a warning, not a seal failure
     * (the primary seal already committed) */
    for (int i = 0; i < n_sinks; i++)
        if (append_seal_file(sinks[i], rec, rec_len) != 0)
            fprintf(stderr, "pq-audit: warning: could not mirror seal to sink '%s'\n", sinks[i]);
    free(rec);

    if (verbose) {
        char hh[2*PQA_HASH_LEN+1], mh[2*PQA_HASH_LEN+1];
        pqa_hex(st.head_hash, PQA_HASH_LEN, hh);
        pqa_hex(mroot, PQA_HASH_LEN, mh);
        printf("sealed %s through seq %llu\n  alg:   %s  (key_epoch %llu)\n  head:  %s\n  merkle:%s\n",
               PQA_SEAL_FILE, (unsigned long long)st.last_seq, sk->alg,
               (unsigned long long)key_epoch, hh, mh);
    }
    return PQA_OK;
}

int pqa_key_load_pass(const char *path, const char *pass, pqsign_key *out)
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "pq-audit: open %s: %s\n", path, strerror(errno)); return PQA_EUSAGE; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return PQA_EUSAGE; }
    uint8_t *raw = malloc((size_t)sz ? (size_t)sz : 1);
    if (!raw) { fclose(f); return PQA_EUSAGE; }
    if (fread(raw, 1, (size_t)sz, f) != (size_t)sz) { free(raw); fclose(f); return PQA_EUSAGE; }
    fclose(f);

    pqsign_armor a;
    int rc = PQA_EUSAGE;
    if (!key_armor_parse(raw, (size_t)sz, &a)) { fprintf(stderr, "pq-audit: '%s' is not a valid key file\n", path); goto out; }
    memset(out, 0, sizeof *out);
    snprintf(out->alg, sizeof out->alg, "%s", a.alg);
    out->is_secret = a.is_secret;
    /* Copy the embedded public key, but leave a.pub intact: key_decrypt feeds
     * it (with pub_len) into the AEAD as AAD, so it must not be NULL here. */
    if (a.pub) {
        out->pub = xmalloc(a.pub_len ? a.pub_len : 1);
        memcpy(out->pub, a.pub, a.pub_len);
        out->pub_len = a.pub_len;
    }
    if (!key_decrypt(&a, pass, &out->key, &out->key_len)) {
        fprintf(stderr, "pq-audit: cannot decrypt '%s' (wrong/missing passphrase?)\n", path);
        free(out->pub); out->pub = NULL;
        armor_free(&a);
        goto out;
    }
    armor_free(&a);
    rc = PQA_OK;
out:
    secure_wipe(raw, (size_t)sz);
    free(raw);
    return rc;
}

int pqa_seal_create(const char *dir, const char *keypath, const char *ringpath,
                    const char *const *sinks, int n_sinks)
{
    pqsign_key sk;
    uint64_t key_epoch = 0;
    if (ringpath) {
        uint32_t ep = 0;
        if (pqa_ring_current(ringpath, &sk, &ep) != PQA_OK) return PQA_EUSAGE;
        key_epoch = ep;
    } else {
        key_load(keypath, &sk);          /* prompts if encrypted; dies on bad */
    }
    int rc = pqa_seal_with_key(dir, &sk, key_epoch, 1, sinks, n_sinks);
    key_free(&sk);
    if (rc == PQA_OK && ringpath)
        printf("  ↳ run 'fs-advance' to destroy this epoch's secret\n");
    return rc;
}

/* verify one seal record against an already-resolved public key */
static int verify_one(const char *dir, uint64_t epoch, uint64_t covers,
                      uint64_t key_epoch, const uint8_t *head,
                      const uint8_t *mroot, const uint8_t *blob, uint32_t blen,
                      const pqsign_key *pk)
{
    uint8_t real_head[PQA_HASH_LEN];
    if (pqa_segment_head_at(dir, covers, real_head) != PQA_OK) return PQA_ETAMPER;
    if (memcmp(real_head, head, PQA_HASH_LEN) != 0) {
        fprintf(stderr, "pq-audit: seal head mismatch at seq %llu\n", (unsigned long long)covers);
        return PQA_ETAMPER;
    }
    uint8_t real_mroot[PQA_HASH_LEN];
    if (merkle_for(dir, covers, real_mroot) != PQA_OK) return PQA_ETAMPER;
    if (memcmp(real_mroot, mroot, PQA_HASH_LEN) != 0) {
        fprintf(stderr, "pq-audit: seal merkle-root mismatch at seq %llu\n", (unsigned long long)covers);
        return PQA_ETAMPER;
    }
    uint8_t digest[PQA_HASH_LEN];
    seal_digest(epoch, covers, key_epoch, head, mroot, digest);
    int v = pqoqs_verify_digest(pk, digest, blob, blen);
    if (v != 0) {
        fprintf(stderr, "pq-audit: seal signature invalid at seq %llu\n", (unsigned long long)covers);
        return (v == 2) ? PQA_ETAMPER : PQA_EUSAGE;
    }
    return PQA_OK;
}

int pqa_seal_verify(const char *dir, const char *pubpath,
                    const char *fspub, const char *anchorpath,
                    const char *seal_file_override,
                    uint64_t *out_seals, uint64_t *out_covered)
{
    /* chain must verify first (gives us the segment epoch) */
    pqa_chain_state st;
    if (pqa_segment_verify(dir, &st, NULL) != PQA_OK) return PQA_ETAMPER;

    /* resolve verification material */
    pqsign_key single;     int have_single = 0;
    pqa_fspub fp;          int have_fp = 0;
    if (fspub) {
        if (!anchorpath) { fprintf(stderr, "pq-audit: --fspub needs --anchor\n"); return PQA_EUSAGE; }
        if (pqa_fspub_load(fspub, &fp) != PQA_OK) return PQA_EUSAGE;
        have_fp = 1;
        /* authenticate the epoch public keys against the SLH-DSA anchor */
        pqsign_key anchor; key_load(anchorpath, &anchor);
        uint8_t mdg[PQA_HASH_LEN];
        pqa_fs_manifest_digest(&fp, mdg);
        int av = pqoqs_verify_digest(&anchor, mdg, fp.anchor_blob, fp.anchor_blob_len);
        key_free(&anchor);
        if (av != 0) {
            fprintf(stderr, "pq-audit: forward-secure manifest failed anchor signature\n");
            pqa_fspub_free(&fp);
            return PQA_ETAMPER;
        }
    } else {
        key_load(pubpath, &single);
        have_single = 1;
    }

    char path[4096];
    if (seal_file_override) {
        if (snprintf(path, sizeof path, "%s", seal_file_override) >= (int)sizeof path) { if (have_single) key_free(&single); if (have_fp) pqa_fspub_free(&fp); return PQA_EUSAGE; }
    } else if (seal_path(path, sizeof path, dir) != 0) { if (have_single) key_free(&single); if (have_fp) pqa_fspub_free(&fp); return PQA_EUSAGE; }
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "pq-audit: open %s: %s\n", path, strerror(errno)); if (have_single) key_free(&single); if (have_fp) pqa_fspub_free(&fp); return PQA_EUSAGE; }

    uint8_t hdr[SEAL_HDR_LEN];
    int rc = PQA_OK;
    if (fread(hdr, 1, SEAL_HDR_LEN, f) != SEAL_HDR_LEN ||
        memcmp(hdr, PQA_SEAL_MAGIC, 8) != 0 || get16(hdr + 8) != PQA_VERSION) {
        fprintf(stderr, "pq-audit: bad seal header\n"); rc = PQA_ETAMPER; goto done;
    }

    uint64_t seals = 0, covered = 0;
    for (;;) {
        uint8_t fx[SEAL_FIXED];
        size_t got = fread(fx, 1, sizeof fx, f);
        if (got == 0 && feof(f)) break;
        if (got != sizeof fx) { rc = PQA_ETAMPER; break; }
        uint64_t covers    = get64(fx + 8);
        uint64_t key_epoch = get64(fx + 16);
        const uint8_t *head  = fx + 24;
        const uint8_t *mroot = fx + 24 + PQA_HASH_LEN;
        uint32_t blen = get32(fx + 24 + 2 * PQA_HASH_LEN);

        uint8_t *blob = malloc(blen ? blen : 1);
        if (!blob) { rc = PQA_EUSAGE; break; }
        if (fread(blob, 1, blen, f) != blen) { free(blob); rc = PQA_ETAMPER; break; }

        const pqsign_key *pk;
        pqsign_key vk;
        if (have_fp) {
            if (key_epoch >= fp.n) { fprintf(stderr, "pq-audit: seal references unknown epoch %llu\n", (unsigned long long)key_epoch); free(blob); rc = PQA_ETAMPER; break; }
            memset(&vk, 0, sizeof vk);
            snprintf(vk.alg, sizeof vk.alg, "%s", fp.alg);
            vk.key = fp.pubs[key_epoch]; vk.key_len = fp.publens[key_epoch];  /* borrowed */
            pk = &vk;
        } else {
            pk = &single;
        }

        int v = verify_one(dir, st.epoch, covers, key_epoch, head, mroot, blob, blen, pk);
        free(blob);
        if (v != PQA_OK) { rc = v; break; }
        seals++;
        if (covers > covered) covered = covers;
    }

    if (rc == PQA_OK) {
        if (out_seals) *out_seals = seals;
        if (out_covered) *out_covered = covered;
    }
done:
    fclose(f);
    if (have_single) key_free(&single);
    if (have_fp) pqa_fspub_free(&fp);
    return rc;
}
