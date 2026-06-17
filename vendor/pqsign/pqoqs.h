/* pqoqs.h — thin liboqs keygen/sign/verify wrapper over pq-sign's key and
 * signature-container library.  The logic here mirrors pq-sign's main.c (which
 * is a CLI, not part of the library); it is the only PQ-signature glue
 * pq-audit needs.  MIT (c) 2026 Jean-Francois Lachance-Caumartin
 */
#ifndef PQOQS_H
#define PQOQS_H

#include <stddef.h>
#include <stdint.h>
#include "pqsign.h"

/* Resolve a user alias (e.g. "ml-dsa-65") or a canonical liboqs name to the
 * canonical name, or NULL if not enabled in this liboqs build. */
const char *pqoqs_canonical_alg(const char *name);

/* Generate a raw keypair for `alg`. *pub is xmalloc'd, *sec is secure_alloc'd
 * (caller secure_free's it with *seclen).  Returns 0 on success, 1 on error. */
int pqoqs_keypair(const char *alg, uint8_t **pub, size_t *publen,
                  uint8_t **sec, size_t *seclen);

/* Generate a keypair for `alg` and write `<base>.pub` / `<base>.key` (armored,
 * the secret encrypted with Argon2id+AES-256-GCM if passphrase != NULL).
 * Returns 0 on success, 1 on error. */
int pqoqs_keygen(const char *alg, const char *base, const char *passphrase);

/* Sign a 32-byte digest with loaded secret key `sk`. Returns a malloc'd PQSIGN
 * detached-signature blob (same container as pq-sign), *out_len set; NULL on
 * error. */
uint8_t *pqoqs_sign_digest(const pqsign_key *sk, const uint8_t digest[32],
                           size_t *out_len);

/* Verify a PQSIGN blob over `digest` against public key `pk`.
 * Returns 0 valid, 2 invalid/mismatched signer, 1 error. */
int pqoqs_verify_digest(const pqsign_key *pk, const uint8_t digest[32],
                        const uint8_t *blob, size_t blob_len);

#endif /* PQOQS_H */
