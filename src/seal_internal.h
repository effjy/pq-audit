/* seal_internal.h — seal core shared with the daemon (M5).  Not public API.
 * MIT (c) 2026 JFLC
 */
#ifndef PQA_SEAL_INTERNAL_H
#define PQA_SEAL_INTERNAL_H

#include "pqaudit.h"
#include "pqsign.h"     /* vendored: pqsign_key */

/* Seal the current chain head + Merkle root with an already-loaded secret key.
 * `key_epoch` is recorded in the seal (0 for a plain key).  `verbose` prints
 * the human-readable summary.  Returns PQA_OK / PQA_ETAMPER / PQA_EUSAGE. */
int pqa_seal_with_key(const char *dir, const pqsign_key *sk, uint64_t key_epoch,
                      int verbose, const char *const *sinks, int n_sinks);

/* Load an armored secret key non-interactively, taking the passphrase from
 * `pass` (NULL for an unencrypted key).  Unlike the vendored key_load this
 * never prompts and never aborts.  Returns PQA_OK / PQA_EUSAGE.  Caller
 * key_free()s *out on success. */
int pqa_key_load_pass(const char *path, const char *pass, pqsign_key *out);

#endif /* PQA_SEAL_INTERNAL_H */
