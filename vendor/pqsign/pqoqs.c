/* pqoqs.c — liboqs glue, lifted from pq-sign's main.c.  MIT (c) 2026 JFLC */
#include "pqoqs.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <oqs/oqs.h>

struct alg_alias { const char *alias; const char *canonical; };
static const struct alg_alias ALIASES[] = {
    { "ml-dsa-44",    "ML-DSA-44" },
    { "ml-dsa-65",    "ML-DSA-65" },
    { "ml-dsa-87",    "ML-DSA-87" },
    { "slh-dsa-128f", "SPHINCS+-SHA2-128f-simple" },
    { "slh-dsa-192f", "SPHINCS+-SHA2-192f-simple" },
    { "slh-dsa-256f", "SPHINCS+-SHA2-256f-simple" },
    { NULL, NULL }
};

const char *pqoqs_canonical_alg(const char *name)
{
    for (const struct alg_alias *a = ALIASES; a->alias; a++)
        if (strcasecmp(name, a->alias) == 0)
            return a->canonical;
    if (OQS_SIG_alg_is_enabled(name))
        return name;
    return NULL;
}

int pqoqs_keypair(const char *alg, uint8_t **pub, size_t *publen,
                  uint8_t **sec, size_t *seclen)
{
    const char *canon = pqoqs_canonical_alg(alg);
    if (!canon) { warn("unknown or disabled algorithm: %s", alg); return 1; }
    OQS_SIG *sig = OQS_SIG_new(canon);
    if (!sig) { warn("OQS_SIG_new failed for %s", canon); return 1; }

    uint8_t *pk = xmalloc(sig->length_public_key);
    uint8_t *sk = secure_alloc(sig->length_secret_key);
    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
        warn("key generation failed");
        free(pk); secure_free(sk, sig->length_secret_key);
        OQS_SIG_free(sig); return 1;
    }
    *pub = pk; *publen = sig->length_public_key;
    *sec = sk; *seclen = sig->length_secret_key;
    OQS_SIG_free(sig);
    return 0;
}

int pqoqs_keygen(const char *alg, const char *base, const char *passphrase)
{
    const char *canon = pqoqs_canonical_alg(alg);
    if (!canon) { warn("unknown or disabled algorithm: %s", alg); return 1; }
    uint8_t *pub = NULL, *sec = NULL;
    size_t publen = 0, seclen = 0;
    if (pqoqs_keypair(canon, &pub, &publen, &sec, &seclen) != 0) return 1;

    char path[4096];
    snprintf(path, sizeof path, "%s.pub", base);
    key_write_public(path, canon, pub, publen);
    snprintf(path, sizeof path, "%s.key", base);
    key_write_secret(path, canon, sec, seclen, pub, publen, passphrase);

    secure_wipe(sec, seclen);
    secure_free(sec, seclen);
    free(pub);
    return 0;
}

uint8_t *pqoqs_sign_digest(const pqsign_key *sk, const uint8_t digest[32],
                           size_t *out_len)
{
    if (!sk->is_secret || !sk->pub) { warn("not a usable secret key"); return NULL; }
    OQS_SIG *sig = OQS_SIG_new(sk->alg);
    if (!sig) { warn("OQS_SIG_new failed for %s", sk->alg); return NULL; }

    uint8_t *signature = xmalloc(sig->length_signature);
    size_t siglen = 0;
    uint8_t *blob = NULL;
    if (OQS_SIG_sign(sig, signature, &siglen, digest, 32, sk->key) != OQS_SUCCESS) {
        warn("signing failed");
        goto out;
    }
    blob = sigfile_build(sk->alg, sk->pub, sk->pub_len, signature, siglen, out_len);
out:
    secure_wipe(signature, sig->length_signature);
    free(signature);
    OQS_SIG_free(sig);
    return blob;
}

int pqoqs_verify_digest(const pqsign_key *pk, const uint8_t digest[32],
                        const uint8_t *blob, size_t blob_len)
{
    pqsign_sigfile sf;
    if (!sigfile_parse(blob, blob_len, &sf)) { warn("malformed signature blob"); return 1; }

    /* Bind signature to signer: the blob carries SHA-256(pubkey); reject early
     * (constant-time) if it does not match the key we were handed. */
    uint8_t fpr[32];
    sha256(pk->key, pk->key_len, fpr);
    int rc;
    if (!ct_equal(fpr, sf.pub_fpr, 32)) {
        rc = 2;                                   /* wrong signer */
        goto out;
    }
    if (strcmp(pk->alg, sf.alg) != 0) { rc = 2; goto out; }

    OQS_SIG *sig = OQS_SIG_new(pk->alg);
    if (!sig) { warn("OQS_SIG_new failed for %s", pk->alg); rc = 1; goto out; }
    OQS_STATUS st = OQS_SIG_verify(sig, digest, 32, sf.sig, sf.sig_len, pk->key);
    OQS_SIG_free(sig);
    rc = (st == OQS_SUCCESS) ? 0 : 2;
out:
    sigfile_free(&sf);
    return rc;
}
