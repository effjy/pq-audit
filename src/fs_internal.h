/* fs_internal.h — cross-file seams shared by fs.c and seal.c (M3).
 * Not a public API.  MIT (c) 2026 JFLC
 */
#ifndef PQA_FS_INTERNAL_H
#define PQA_FS_INTERNAL_H

#include "pqaudit.h"
#include "pqsign.h"     /* vendored: pqsign_key */

/* Load the ring's current-epoch secret into a pqsign_key (public key embedded)
 * and report which epoch it is.  Returns PQA_OK / PQA_EUSAGE.  On success the
 * caller must key_free(out_sk). */
int pqa_ring_current(const char *ringpath, pqsign_key *out_sk, uint32_t *out_epoch);

/* Parsed verifier bundle (epoch public keys + anchor signature). */
typedef struct {
    char       alg[64];
    char       anchor_alg[64];
    uint32_t   n;
    uint8_t  **pubs;
    size_t    *publens;
    uint8_t   *anchor_blob;
    size_t     anchor_blob_len;
} pqa_fspub;

int  pqa_fspub_load(const char *path, pqa_fspub *out);
void pqa_fspub_free(pqa_fspub *fp);

/* Digest the anchor signs/verifies over: binds all epoch public keys. */
void pqa_fs_manifest_digest(const pqa_fspub *fp, uint8_t out[PQA_HASH_LEN]);

#endif /* PQA_FS_INTERNAL_H */
