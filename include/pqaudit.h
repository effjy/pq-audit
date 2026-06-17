/* pq-audit — tamper-evident post-quantum audit log
 * Shared declarations.  MIT (c) 2026 Jean-Francois Lachance-Caumartin
 */
#ifndef PQAUDIT_H
#define PQAUDIT_H

#include <stddef.h>
#include <stdint.h>

#define PQA_MAGIC      "PQAUDIT\0"   /* 8 bytes incl. trailing NUL */
#define PQA_MAGIC_LEN  8
#define PQA_VERSION    1
#define PQA_HASH_LEN   32            /* SHA-256 */

/* flags (segment header) */
#define PQA_FLAG_ENC_PAYLOAD  0x0001 /* payloads AES-256-GCM (not yet in M1) */
#define PQA_FLAG_FORWARD_SEC  0x0002 /* forward-secure sealing (not yet in M1) */

/* domain separation, mirroring pq-sign's style */
#define PQA_DS_ENTRY     "pq-audit/entry/v1"
#define PQA_DS_SEAL      "pq-audit/seal/v1"
#define PQA_DS_MANIFEST  "pq-audit/fs-manifest/v1"
/* Merkle domain separation: one-byte prefixes (CT-style) */
#define PQA_MT_LEAF  0x00
#define PQA_MT_NODE  0x01

/* exit codes — mirror pq-sign: 0 ok, 2 tamper/invalid, 1 usage/IO */
#define PQA_OK        0
#define PQA_EUSAGE    1
#define PQA_ETAMPER   2

/* Segments are named audit-NNNNNN.palog; the highest index is the active one.
 * They form one logical log: continuous sequence numbers and a hash chain that
 * links across boundaries via each header's prev_segment_root. */
#define PQA_SEG_FMT      "audit-%06u.palog"
#define PQA_SEG_PREFIX   "audit-"
#define PQA_SEG_SUFFIX   ".palog"
#define PQA_SEAL_FILE    "audit.seal"
#define PQA_SEAL_MAGIC   "PQASEAL\0"
#define PQA_RING_MAGIC   "PQAFSRG\0"
#define PQA_FSPUB_MAGIC  "PQAFSPB\0"

/* ---- util.c ---- */
int  pqa_sha256(const void *data, size_t len, uint8_t out[PQA_HASH_LEN]);
void pqa_hex(const uint8_t *in, size_t len, char *out /* 2*len+1 */);
uint64_t pqa_now_realtime_ns(void);
uint64_t pqa_now_mono_ns(void);
/* atomically (temp+fsync+rename) replace path with buf */
int  pqa_write_atomic(const char *path, const void *buf, size_t len, int mode);

/* ---- segment.c ---- */
typedef struct {
    uint16_t version;
    uint16_t flags;
    uint64_t epoch;
    uint64_t seq0;
    uint8_t  prev_segment_root[PQA_HASH_LEN];
} pqa_seg_header;

/* current chain state after the last committed entry */
typedef struct {
    uint64_t last_seq;                 /* seq of last entry, or UINT64_MAX if none */
    uint8_t  head_hash[PQA_HASH_LEN];  /* chain head (header-derived if empty) */
    uint64_t count;                    /* number of entries */
    uint64_t epoch;                    /* segment epoch (from header) */
} pqa_chain_state;

int pqa_segment_init(const char *dir, uint16_t flags, uint64_t epoch,
                     const uint8_t prev_segment_root[PQA_HASH_LEN]);

/* append one entry; payload may be NULL iff payload_len==0.  When non-NULL,
 * *out_seq and out_head[] receive the new entry's sequence and chain head. */
int pqa_segment_append(const char *dir, uint16_t src_id, uint8_t level,
                       const void *payload, uint32_t payload_len,
                       uint64_t *out_seq, uint8_t out_head[PQA_HASH_LEN]);

/* walk the whole segment, verifying the chain.  Returns PQA_OK,
 * PQA_ETAMPER (sets *bad_seq to the failing sequence), or PQA_EUSAGE. */
int pqa_segment_verify(const char *dir, pqa_chain_state *out, uint64_t *bad_seq);

/* Verify the chain and return the chain head as of entry `target_seq`.
 * target_seq==UINT64_MAX means the final head.  Returns PQA_OK, PQA_ETAMPER,
 * or PQA_EUSAGE (incl. target_seq beyond the log). */
int pqa_segment_head_at(const char *dir, uint64_t target_seq,
                        uint8_t out_head[PQA_HASH_LEN]);

/* Verify the chain and collect the per-entry chain hashes for seqs
 * [seq0 .. upto] into a freshly malloc'd array (*out_hashes, *out_n).
 * Caller free()s. upto==UINT64_MAX collects all entries. */
int pqa_segment_collect(const char *dir, uint64_t upto,
                        uint8_t (**out_hashes)[PQA_HASH_LEN], uint64_t *out_n);

/* compute the seed hash from a header (chain root before any entry) */
void pqa_header_seed(const pqa_seg_header *h, uint8_t out[PQA_HASH_LEN]);

/* Roll over to a new active segment: verify the current segment, then create
 * the next one seeded by its final head (prev_segment_root linkage) with the
 * continuing seq0.  The current segment must be non-empty.  Returns PQA_OK /
 * PQA_ETAMPER / PQA_EUSAGE; *out_new_idx receives the new segment index. */
int pqa_segment_rotate(const char *dir, unsigned *out_new_idx);

/* Number of entries in the active (highest-index) segment, into *out. */
int pqa_segment_active_count(const char *dir, uint64_t *out);

/* ---- merkle.c (M4) ---- */

/* Compute the Merkle root over `n` leaves (each a 32-byte entry hash).
 * n==0 yields the all-zero root.  CT-style domain-separated. */
void pqa_merkle_root(const uint8_t (*leaves)[PQA_HASH_LEN], uint64_t n,
                     uint8_t out_root[PQA_HASH_LEN]);

/* Emit a binary inclusion proof for entry `seq` to stdout, proving membership
 * in the Merkle tree the most recent seal commits to.  Returns PQA_OK /
 * PQA_ETAMPER / PQA_EUSAGE. */
int pqa_proof_emit(const char *dir, uint64_t seq);

/* Read a binary inclusion proof from stdin and check it recomputes `root_hex`.
 * Returns PQA_OK (valid) / PQA_ETAMPER (invalid) / PQA_EUSAGE. */
int pqa_proof_check(const char *root_hex);

/* ---- seal.c (M2: post-quantum sealing via vendored pq-sign) ---- */

/* Sign the current chain head + Merkle root with the secret key at `keypath`
 * (key_epoch 0) and append to audit.seal.  ringpath!=NULL selects forward-
 * secure mode: sign with the keyring's current epoch key (key_epoch tracked).
 * Exactly one of keypath/ringpath is non-NULL.  Each seal is also mirrored to
 * the `n_sinks` off-box append-only files in `sinks`. */
int pqa_seal_create(const char *dir, const char *keypath, const char *ringpath,
                    const char *const *sinks, int n_sinks);

/* Verify every seal.  Non-FS: pubpath is a single public key.  FS: fspub +
 * anchorpath authenticate per-epoch public keys (the manifest is checked
 * against the SLH-DSA anchor first).  seal_file_override!=NULL verifies the
 * chain against that seal-journal (e.g. an off-box sink copy) instead of
 * dir/audit.seal.  Sets *out_seals / *out_covered. */
int pqa_seal_verify(const char *dir, const char *pubpath,
                    const char *fspub, const char *anchorpath,
                    const char *seal_file_override,
                    uint64_t *out_seals, uint64_t *out_covered);

/* ---- fs.c (M3: forward security) ---- */

/* Generate an SLH-DSA anchor keypair (<base>.anchor.{pub,key}), `epochs`
 * independent epoch keypairs of `alg`, a secret keyring (<base>.fsring), and
 * the verifier bundle (<base>.fspub) carrying the epoch public keys signed by
 * the anchor.  Returns PQA_OK / PQA_EUSAGE. */
int pqa_fs_init(const char *base, const char *alg, const char *anchor_alg,
                uint32_t epochs);

/* Destroy the current epoch's secret key in the ring and advance the cursor so
 * the next seal uses the following epoch.  Past seals become unforgeable. */
int pqa_fs_advance(const char *ringpath);

/* ---- daemon.c (M5: ingest daemon) ---- */

typedef struct {
    const char *dir;            /* audit directory */
    const char *socket_path;    /* unix socket to listen on */
    const char *keypath;        /* sealing: plain key …            */
    const char *ringpath;       /*          … or forward-secure ring */
    const char *passphrase;     /* for an encrypted --key (NULL = none) */
    uint16_t    src_id;         /* src tag stamped on ingested entries */
    uint64_t    seal_every;     /* auto-seal after N entries (0 = off) */
    uint64_t    seal_interval;  /* auto-seal every T seconds   (0 = off) */
    const char *const *sinks;   /* off-box seal-mirror files */
    int         n_sinks;
    uint64_t    max_entries;    /* rotate active segment past N entries (0=off) */
} pqa_run_opts;

/* Run the ingest daemon: accept NDJSON lines over the unix socket, append each
 * as an entry, auto-seal per the schedule, and seal once more on SIGINT/SIGTERM
 * before exiting.  Returns PQA_OK on clean shutdown, PQA_EUSAGE on error. */
int pqa_run(const pqa_run_opts *o);

#endif /* PQAUDIT_H */
