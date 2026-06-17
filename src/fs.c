/* fs.c — forward security: per-epoch keys anchored by one SLH-DSA signature.
 * MIT (c) 2026 Jean-Francois Lachance-Caumartin
 *
 * fs-init pre-generates N independent epoch keypairs (ML-DSA by default) plus
 * one long-term SLH-DSA anchor.  The anchor signs a manifest of all epoch
 * public keys; that signature travels in the verifier bundle (<base>.fspub).
 * Each seal is made with the current epoch's secret; fs-advance destroys that
 * secret and moves the cursor forward.  An attacker who captures the box at
 * epoch e gets only key e (and later, undestroyed) secrets — seals from epochs
 * < e cannot be re-forged.  No new cryptography: ML-DSA + SLH-DSA composed.
 *
 * <base>.fsring (secret, 0600):
 *   magic ver:u16 alg[64] n:u32 current:u32
 *   per epoch: present:u8 seclen:u32 sec[] publen:u32 pub[]
 * <base>.fspub (public):
 *   magic ver:u16 alg[64] anchor_alg[64] n:u32
 *   per epoch: publen:u32 pub[]
 *   anchor_blob_len:u32 anchor_blob[]   (PQSIGN container over manifest digest)
 */
#define _POSIX_C_SOURCE 200809L
#include "fs_internal.h"
#include "pqoqs.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>

static void put16(uint8_t *p, uint16_t v){ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void put32(uint8_t *p, uint32_t v){ for(int i=0;i<4;i++) p[i]=(uint8_t)(v>>(8*i)); }
static uint16_t get16(const uint8_t *p){ return (uint16_t)p[0]|((uint16_t)p[1]<<8); }
static uint32_t get32(const uint8_t *p){ uint32_t v=0; for(int i=0;i<4;i++) v|=(uint32_t)p[i]<<(8*i); return v; }

/* ---- manifest digest ---- */
void pqa_fs_manifest_digest(const pqa_fspub *fp, uint8_t out[PQA_HASH_LEN])
{
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    unsigned int ol = 0;
    uint8_t algbuf[64]; memset(algbuf, 0, sizeof algbuf);
    snprintf((char *)algbuf, sizeof algbuf, "%s", fp->alg);
    uint8_t nb[4]; put32(nb, fp->n);
    EVP_DigestInit_ex(c, EVP_sha256(), NULL);
    EVP_DigestUpdate(c, PQA_DS_MANIFEST, strlen(PQA_DS_MANIFEST));
    EVP_DigestUpdate(c, algbuf, sizeof algbuf);
    EVP_DigestUpdate(c, nb, 4);
    for (uint32_t i = 0; i < fp->n; i++) {
        uint8_t lb[4]; put32(lb, (uint32_t)fp->publens[i]);
        EVP_DigestUpdate(c, lb, 4);
        EVP_DigestUpdate(c, fp->pubs[i], fp->publens[i]);
    }
    EVP_DigestFinal_ex(c, out, &ol);
    EVP_MD_CTX_free(c);
}

/* ---- read a whole file ---- */
static uint8_t *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    uint8_t *b = malloc((size_t)sz ? (size_t)sz : 1);
    if (!b) { fclose(f); return NULL; }
    if (fread(b, 1, (size_t)sz, f) != (size_t)sz) { free(b); fclose(f); return NULL; }
    fclose(f);
    *len = (size_t)sz;
    return b;
}

/* ================= fs-init ================= */
int pqa_fs_init(const char *base, const char *alg, const char *anchor_alg,
                uint32_t epochs)
{
    if (epochs == 0 || epochs > 100000) { warn("epochs out of range"); return PQA_EUSAGE; }
    const char *canon = pqoqs_canonical_alg(alg);
    const char *acanon = pqoqs_canonical_alg(anchor_alg);
    if (!canon)  { warn("unknown epoch alg: %s", alg); return PQA_EUSAGE; }
    if (!acanon) { warn("unknown anchor alg: %s", anchor_alg); return PQA_EUSAGE; }

    char path[4096];
    /* anchor keypair on disk (the secret can be deleted/offline after this) */
    snprintf(path, sizeof path, "%s.anchor", base);
    if (pqoqs_keygen(acanon, path, NULL) != 0) return PQA_EUSAGE;

    /* generate epoch keypairs */
    uint8_t **pubs = xcalloc(epochs, sizeof *pubs);
    size_t  *publ  = xcalloc(epochs, sizeof *publ);
    uint8_t **secs = xcalloc(epochs, sizeof *secs);
    size_t  *secl  = xcalloc(epochs, sizeof *secl);
    int rc = PQA_EUSAGE;
    for (uint32_t i = 0; i < epochs; i++)
        if (pqoqs_keypair(canon, &pubs[i], &publ[i], &secs[i], &secl[i]) != 0)
            goto cleanup;

    /* build the verifier bundle in memory and sign its manifest with anchor */
    pqa_fspub fp;
    memset(&fp, 0, sizeof fp);
    snprintf(fp.alg, sizeof fp.alg, "%s", canon);
    snprintf(fp.anchor_alg, sizeof fp.anchor_alg, "%s", acanon);
    fp.n = epochs; fp.pubs = pubs; fp.publens = publ;

    uint8_t mdg[PQA_HASH_LEN];
    pqa_fs_manifest_digest(&fp, mdg);

    pqsign_key anchor_sk;
    snprintf(path, sizeof path, "%s.anchor.key", base);
    key_load(path, &anchor_sk);          /* freshly generated, unencrypted */
    size_t blob_len = 0;
    uint8_t *blob = pqoqs_sign_digest(&anchor_sk, mdg, &blob_len);
    key_free(&anchor_sk);
    if (!blob) goto cleanup;

    /* serialize <base>.fspub */
    size_t fpsize = 8 + 2 + 64 + 64 + 4;
    for (uint32_t i = 0; i < epochs; i++) fpsize += 4 + publ[i];
    fpsize += 4 + blob_len;
    uint8_t *fb = malloc(fpsize), *p = fb;
    if (!fb) { free(blob); goto cleanup; }
    memcpy(p, PQA_FSPUB_MAGIC, 8); p += 8;
    put16(p, PQA_VERSION); p += 2;
    memset(p, 0, 64); snprintf((char *)p, 64, "%s", canon);  p += 64;
    memset(p, 0, 64); snprintf((char *)p, 64, "%s", acanon); p += 64;
    put32(p, epochs); p += 4;
    for (uint32_t i = 0; i < epochs; i++) {
        put32(p, (uint32_t)publ[i]); p += 4;
        memcpy(p, pubs[i], publ[i]);  p += publ[i];
    }
    put32(p, (uint32_t)blob_len); p += 4;
    memcpy(p, blob, blob_len);
    free(blob);
    snprintf(path, sizeof path, "%s.fspub", base);
    int wr = pqa_write_atomic(path, fb, fpsize, 0644);
    free(fb);
    if (wr != 0) goto cleanup;

    /* serialize <base>.fsring (secrets) */
    size_t rsize = 8 + 2 + 64 + 4 + 4;
    for (uint32_t i = 0; i < epochs; i++) rsize += 1 + 4 + secl[i] + 4 + publ[i];
    uint8_t *rb = malloc(rsize); p = rb;
    if (!rb) goto cleanup;
    memcpy(p, PQA_RING_MAGIC, 8); p += 8;
    put16(p, PQA_VERSION); p += 2;
    memset(p, 0, 64); snprintf((char *)p, 64, "%s", canon); p += 64;
    put32(p, epochs); p += 4;
    put32(p, 0); p += 4;                 /* current epoch = 0 */
    for (uint32_t i = 0; i < epochs; i++) {
        *p++ = 1;
        put32(p, (uint32_t)secl[i]); p += 4; memcpy(p, secs[i], secl[i]); p += secl[i];
        put32(p, (uint32_t)publ[i]); p += 4; memcpy(p, pubs[i], publ[i]); p += publ[i];
    }
    snprintf(path, sizeof path, "%s.fsring", base);
    wr = pqa_write_atomic(path, rb, rsize, 0600);
    secure_wipe(rb, rsize);
    free(rb);
    if (wr != 0) goto cleanup;

    printf("Forward-secure keyring initialized\n"
           "  epochs:  %u × %s\n  anchor:  %s\n"
           "  ring:    %s.fsring  (secret — protect / keep off the monitored box)\n"
           "  bundle:  %s.fspub + %s.anchor.pub  (verifier)\n",
           epochs, canon, acanon, base, base, base);
    rc = PQA_OK;

cleanup:
    for (uint32_t i = 0; i < epochs; i++) {
        free(pubs[i]);
        if (secs[i]) { secure_wipe(secs[i], secl[i]); secure_free(secs[i], secl[i]); }
    }
    free(pubs); free(publ); free(secs); free(secl);
    return rc;
}

/* ================= ring load / advance ================= */
struct ring_slot { int present; uint8_t *sec; size_t seclen; uint8_t *pub; size_t publen; };
struct ring { char alg[64]; uint32_t n, current; struct ring_slot *slot; };

static int ring_parse(const uint8_t *b, size_t len, struct ring *r)
{
    if (len < 8 + 2 + 64 + 4 + 4) return -1;
    if (memcmp(b, PQA_RING_MAGIC, 8) != 0) return -1;
    const uint8_t *p = b + 8;
    if (get16(p) != PQA_VERSION) return -1;
    p += 2;
    memcpy(r->alg, p, 64); r->alg[63] = 0; p += 64;
    r->n = get32(p); p += 4;
    r->current = get32(p); p += 4;
    if (r->n == 0 || r->n > 100000 || r->current > r->n) return -1;
    r->slot = xcalloc(r->n, sizeof *r->slot);
    const uint8_t *end = b + len;
    for (uint32_t i = 0; i < r->n; i++) {
        if (p + 1 + 4 > end) return -1;
        r->slot[i].present = *p++;
        uint32_t sl = get32(p); p += 4;
        if (p + sl + 4 > end) return -1;
        if (sl) { r->slot[i].sec = secure_alloc(sl); memcpy(r->slot[i].sec, p, sl); }
        r->slot[i].seclen = sl; p += sl;
        uint32_t pl = get32(p); p += 4;
        if (p + pl > end) return -1;
        r->slot[i].pub = xmalloc(pl ? pl : 1); memcpy(r->slot[i].pub, p, pl);
        r->slot[i].publen = pl; p += pl;
    }
    return 0;
}

static void ring_free(struct ring *r)
{
    if (!r->slot) return;
    for (uint32_t i = 0; i < r->n; i++) {
        if (r->slot[i].sec) { secure_wipe(r->slot[i].sec, r->slot[i].seclen); secure_free(r->slot[i].sec, r->slot[i].seclen); }
        free(r->slot[i].pub);
    }
    free(r->slot);
    r->slot = NULL;
}

static int ring_serialize_and_write(const char *path, const struct ring *r)
{
    size_t sz = 8 + 2 + 64 + 4 + 4;
    for (uint32_t i = 0; i < r->n; i++) sz += 1 + 4 + r->slot[i].seclen + 4 + r->slot[i].publen;
    uint8_t *b = malloc(sz), *p = b;
    if (!b) return -1;
    memcpy(p, PQA_RING_MAGIC, 8); p += 8;
    put16(p, PQA_VERSION); p += 2;
    memset(p, 0, 64); snprintf((char *)p, 64, "%s", r->alg); p += 64;
    put32(p, r->n); p += 4;
    put32(p, r->current); p += 4;
    for (uint32_t i = 0; i < r->n; i++) {
        *p++ = (uint8_t)r->slot[i].present;
        put32(p, (uint32_t)r->slot[i].seclen); p += 4;
        memcpy(p, r->slot[i].sec ? r->slot[i].sec : (uint8_t *)"", r->slot[i].seclen); p += r->slot[i].seclen;
        put32(p, (uint32_t)r->slot[i].publen); p += 4;
        memcpy(p, r->slot[i].pub, r->slot[i].publen); p += r->slot[i].publen;
    }
    int rc = pqa_write_atomic(path, b, sz, 0600);
    secure_wipe(b, sz);
    free(b);
    return rc;
}

int pqa_ring_current(const char *ringpath, pqsign_key *out_sk, uint32_t *out_epoch)
{
    size_t len; uint8_t *b = slurp(ringpath, &len);
    if (!b) { warn("cannot read ring %s", ringpath); return PQA_EUSAGE; }
    struct ring r; memset(&r, 0, sizeof r);
    if (ring_parse(b, len, &r) != 0) { secure_wipe(b, len); free(b); warn("malformed ring"); ring_free(&r); return PQA_EUSAGE; }
    secure_wipe(b, len); free(b);

    int rc = PQA_EUSAGE;
    if (r.current >= r.n) { warn("keyring exhausted — all epochs used"); goto out; }
    struct ring_slot *s = &r.slot[r.current];
    if (!s->present || s->seclen == 0) { warn("current epoch secret already destroyed"); goto out; }

    memset(out_sk, 0, sizeof *out_sk);
    snprintf(out_sk->alg, sizeof out_sk->alg, "%s", r.alg);
    out_sk->is_secret = true;
    out_sk->key = secure_alloc(s->seclen); memcpy(out_sk->key, s->sec, s->seclen); out_sk->key_len = s->seclen;
    out_sk->pub = xmalloc(s->publen); memcpy(out_sk->pub, s->pub, s->publen); out_sk->pub_len = s->publen;
    *out_epoch = r.current;
    rc = PQA_OK;
out:
    ring_free(&r);
    return rc;
}

int pqa_fs_advance(const char *ringpath)
{
    size_t len; uint8_t *b = slurp(ringpath, &len);
    if (!b) { warn("cannot read ring %s", ringpath); return PQA_EUSAGE; }
    struct ring r; memset(&r, 0, sizeof r);
    if (ring_parse(b, len, &r) != 0) { secure_wipe(b, len); free(b); ring_free(&r); warn("malformed ring"); return PQA_EUSAGE; }
    secure_wipe(b, len); free(b);

    if (r.current >= r.n) { warn("keyring already exhausted"); ring_free(&r); return PQA_EUSAGE; }
    uint32_t destroyed = r.current;
    struct ring_slot *s = &r.slot[r.current];
    if (s->sec) { secure_wipe(s->sec, s->seclen); secure_free(s->sec, s->seclen); s->sec = NULL; }
    s->seclen = 0; s->present = 0;
    r.current += 1;

    int rc = ring_serialize_and_write(ringpath, &r);
    ring_free(&r);
    if (rc != 0) { warn("failed to write advanced ring"); return PQA_EUSAGE; }
    printf("destroyed epoch %u secret; next seal uses epoch %u%s\n",
           destroyed, r.current, r.current >= r.n ? " (ring now exhausted)" : "");
    return PQA_OK;
}

/* ================= fspub load ================= */
int pqa_fspub_load(const char *path, pqa_fspub *out)
{
    size_t len; uint8_t *b = slurp(path, &len);
    if (!b) { warn("cannot read fspub %s", path); return PQA_EUSAGE; }
    memset(out, 0, sizeof *out);
    if (len < 8 + 2 + 64 + 64 + 4 || memcmp(b, PQA_FSPUB_MAGIC, 8) != 0) { free(b); warn("bad fspub magic"); return PQA_EUSAGE; }
    const uint8_t *p = b + 8, *end = b + len;
    if (get16(p) != PQA_VERSION) { free(b); return PQA_EUSAGE; } p += 2;
    memcpy(out->alg, p, 64); out->alg[63]=0; p += 64;
    memcpy(out->anchor_alg, p, 64); out->anchor_alg[63]=0; p += 64;
    out->n = get32(p); p += 4;
    if (out->n == 0 || out->n > 100000) { free(b); return PQA_EUSAGE; }
    out->pubs = xcalloc(out->n, sizeof *out->pubs);
    out->publens = xcalloc(out->n, sizeof *out->publens);
    for (uint32_t i = 0; i < out->n; i++) {
        if (p + 4 > end) goto bad;
        uint32_t pl = get32(p); p += 4;
        if (p + pl > end) goto bad;
        out->pubs[i] = xmalloc(pl ? pl : 1); memcpy(out->pubs[i], p, pl);
        out->publens[i] = pl; p += pl;
    }
    if (p + 4 > end) goto bad;
    out->anchor_blob_len = get32(p); p += 4;
    if (p + out->anchor_blob_len > end) goto bad;
    out->anchor_blob = xmalloc(out->anchor_blob_len ? out->anchor_blob_len : 1);
    memcpy(out->anchor_blob, p, out->anchor_blob_len);
    free(b);
    return PQA_OK;
bad:
    free(b);
    pqa_fspub_free(out);
    warn("malformed fspub");
    return PQA_EUSAGE;
}

void pqa_fspub_free(pqa_fspub *fp)
{
    if (fp->pubs) for (uint32_t i = 0; i < fp->n; i++) free(fp->pubs[i]);
    free(fp->pubs); free(fp->publens); free(fp->anchor_blob);
    memset(fp, 0, sizeof *fp);
}
