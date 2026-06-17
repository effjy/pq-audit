/* main.c — CLI dispatch for pq-audit (M1: init / log / verify).
 * MIT (c) 2026 Jean-Francois Lachance-Caumartin
 */
#define _POSIX_C_SOURCE 200809L
#include "pqaudit.h"
#include "pqoqs.h"      /* vendored: pqoqs_keygen */
#include "pqsign.h"     /* vendored: prompt_passphrase, secure_wipe */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int usage(void)
{
    fprintf(stderr,
        "pq-audit — tamper-evident post-quantum audit log\n\n"
        "  pq-audit init     --dir <d>\n"
        "  pq-audit log      --dir <d> [--src <n>] [--level <n>]   (payload on stdin)\n"
        "  pq-audit keygen   --out <base> [--alg ml-dsa-65] [--encrypt]\n"
        "  pq-audit seal     --dir <d> (--key <base.key> | --ring <base.fsring>)\n"
        "                    [--sink <file> ...]\n"
        "  pq-audit verify   --dir <d> [--pub <base.pub>] [--seal-file <sink>]\n"
        "                    [--fspub <b.fspub> --anchor <b.anchor.pub>]\n"
        "  pq-audit fs-init  --out <base> [--alg ml-dsa-65] [--anchor slh-dsa-128f]\n"
        "                    --epochs <N>\n"
        "  pq-audit fs-advance --ring <base.fsring>\n"
        "  pq-audit rotate   --dir <d>                      (start a new segment)\n"
        "  pq-audit proof    --dir <d> --seq <n>            (binary proof to stdout)\n"
        "  pq-audit check-proof --root <hex>               (proof on stdin)\n"
        "  pq-audit run      --dir <d> --ingest unix:<path>\n"
        "                    (--key <k> | --ring <r>) [--src <n>]\n"
        "                    [--seal-every <N>] [--seal-interval <secs>]\n"
        "                    [--max-entries <N>] [--sink <file> ...] [--passphrase-fd <n>]\n"
        "                    (passphrase also via env PQA_PASSPHRASE)\n"
        "  pq-audit version\n");
    return PQA_EUSAGE;
}

static int has_flag(int argc, char **argv, const char *name)
{
    for (int i = 2; i < argc; i++) if (strcmp(argv[i], name) == 0) return 1;
    return 0;
}

/* collect every value of a repeated option (e.g. --sink) into out[] (cap max) */
static int collect_opt(int argc, char **argv, const char *name,
                       const char **out, int cap)
{
    int n = 0;
    for (int i = 2; i + 1 < argc && n < cap; i++)
        if (strcmp(argv[i], name) == 0) out[n++] = argv[i + 1];
    return n;
}
#define MAX_SINKS 8

/* tiny option lookup: returns value of --name, or def */
static const char *opt(int argc, char **argv, const char *name, const char *def)
{
    for (int i = 2; i + 1 < argc; i++)
        if (strcmp(argv[i], name) == 0) return argv[i + 1];
    return def;
}

static int cmd_init(int argc, char **argv)
{
    const char *dir = opt(argc, argv, "--dir", NULL);
    if (!dir) return usage();
    int rc = pqa_segment_init(dir, 0, pqa_now_realtime_ns(), NULL);
    if (rc == PQA_OK) printf("initialized audit segment in %s\n", dir);
    return rc;
}

static int cmd_log(int argc, char **argv)
{
    const char *dir = opt(argc, argv, "--dir", NULL);
    if (!dir) return usage();
    uint16_t src = (uint16_t)atoi(opt(argc, argv, "--src", "0"));
    uint8_t level = (uint8_t)atoi(opt(argc, argv, "--level", "0"));

    /* read payload from stdin (bounded; large blobs are a later milestone) */
    size_t cap = 65536, len = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) return PQA_EUSAGE;
    for (;;) {
        if (len == cap) { cap *= 2; uint8_t *n = realloc(buf, cap); if (!n) { free(buf); return PQA_EUSAGE; } buf = n; }
        ssize_t n = read(STDIN_FILENO, buf + len, cap - len);
        if (n < 0) { free(buf); return PQA_EUSAGE; }
        if (n == 0) break;
        len += (size_t)n;
    }
    uint64_t seq = 0; uint8_t head[PQA_HASH_LEN];
    int rc = pqa_segment_append(dir, src, level, buf, (uint32_t)len, &seq, head);
    free(buf);
    if (rc == PQA_OK) {
        char hex[2 * PQA_HASH_LEN + 1];
        pqa_hex(head, PQA_HASH_LEN, hex);
        printf("entry %llu sealed into chain\n  head: %s\n", (unsigned long long)seq, hex);
    }
    return rc;
}

static int cmd_keygen(int argc, char **argv)
{
    const char *base = opt(argc, argv, "--out", NULL);
    if (!base) return usage();
    const char *alg = opt(argc, argv, "--alg", "ml-dsa-65");
    char *pass = NULL;
    if (has_flag(argc, argv, "--encrypt")) {
        pass = prompt_passphrase("Passphrase for secret key: ", true);
        if (!pass) return PQA_EUSAGE;
    }
    int rc = pqoqs_keygen(alg, base, pass);
    if (pass) { secure_wipe(pass, strlen(pass)); free(pass); }
    if (rc == 0) printf("Generated %s keypair\n  public: %s.pub\n  secret: %s.key%s\n",
                        alg, base, base, pass ? "  (encrypted)" : "");
    return rc ? PQA_EUSAGE : PQA_OK;
}

static int cmd_seal(int argc, char **argv)
{
    const char *dir  = opt(argc, argv, "--dir", NULL);
    const char *key  = opt(argc, argv, "--key", NULL);
    const char *ring = opt(argc, argv, "--ring", NULL);
    if (!dir || (!key && !ring) || (key && ring)) return usage();
    const char *sinks[MAX_SINKS];
    int n = collect_opt(argc, argv, "--sink", sinks, MAX_SINKS);
    return pqa_seal_create(dir, key, ring, sinks, n);
}

static int cmd_fs_init(int argc, char **argv)
{
    const char *base = opt(argc, argv, "--out", NULL);
    const char *eps  = opt(argc, argv, "--epochs", NULL);
    if (!base || !eps) return usage();
    const char *alg    = opt(argc, argv, "--alg", "ml-dsa-65");
    const char *anchor = opt(argc, argv, "--anchor", "slh-dsa-128f");
    long n = atol(eps);
    if (n <= 0) return usage();
    return pqa_fs_init(base, alg, anchor, (uint32_t)n);
}

static int cmd_fs_advance(int argc, char **argv)
{
    const char *ring = opt(argc, argv, "--ring", NULL);
    if (!ring) return usage();
    return pqa_fs_advance(ring);
}

static int cmd_rotate(int argc, char **argv)
{
    const char *dir = opt(argc, argv, "--dir", NULL);
    if (!dir) return usage();
    unsigned ni;
    int rc = pqa_segment_rotate(dir, &ni);
    if (rc == PQA_OK) printf("rotated to segment %u\n", ni);
    return rc;
}

static int cmd_proof(int argc, char **argv)
{
    const char *dir = opt(argc, argv, "--dir", NULL);
    const char *seq = opt(argc, argv, "--seq", NULL);
    if (!dir || !seq) return usage();
    return pqa_proof_emit(dir, (uint64_t)strtoull(seq, NULL, 10));
}

static int cmd_check_proof(int argc, char **argv)
{
    const char *root = opt(argc, argv, "--root", NULL);
    if (!root) return usage();
    return pqa_proof_check(root);
}

/* read a passphrase line from a file descriptor (strips a trailing newline) */
static char *read_pass_fd(int fd)
{
    char buf[1024]; size_t len = 0;
    for (;;) {
        ssize_t n = read(fd, buf + len, sizeof buf - 1 - len);
        if (n <= 0) break;
        len += (size_t)n;
        if (len >= sizeof buf - 1) break;
    }
    while (len && (buf[len-1] == '\n' || buf[len-1] == '\r')) len--;
    buf[len] = '\0';
    return strdup(buf);
}

static int cmd_run(int argc, char **argv)
{
    pqa_run_opts o; memset(&o, 0, sizeof o);
    o.dir = opt(argc, argv, "--dir", NULL);
    const char *ingest = opt(argc, argv, "--ingest", NULL);
    o.keypath = opt(argc, argv, "--key", NULL);
    o.ringpath = opt(argc, argv, "--ring", NULL);
    o.src_id = (uint16_t)atoi(opt(argc, argv, "--src", "0"));
    o.seal_every = strtoull(opt(argc, argv, "--seal-every", "0"), NULL, 10);
    o.seal_interval = strtoull(opt(argc, argv, "--seal-interval", "0"), NULL, 10);
    o.max_entries = strtoull(opt(argc, argv, "--max-entries", "0"), NULL, 10);
    const char *sinks[MAX_SINKS];
    o.n_sinks = collect_opt(argc, argv, "--sink", sinks, MAX_SINKS);
    o.sinks = sinks;
    if (!o.dir || !ingest || (!o.keypath && !o.ringpath) || (o.keypath && o.ringpath))
        return usage();

    /* --ingest accepts "unix:/path" or a bare path */
    o.socket_path = strncmp(ingest, "unix:", 5) == 0 ? ingest + 5 : ingest;

    char *pass = NULL;
    const char *pfd = opt(argc, argv, "--passphrase-fd", NULL);
    if (pfd) pass = read_pass_fd(atoi(pfd));
    else { const char *e = getenv("PQA_PASSPHRASE"); if (e) pass = strdup(e); }
    o.passphrase = pass;

    int rc = pqa_run(&o);
    if (pass) { secure_wipe(pass, strlen(pass)); free(pass); }
    return rc;
}

static int cmd_verify(int argc, char **argv)
{
    const char *dir = opt(argc, argv, "--dir", NULL);
    const char *pub = opt(argc, argv, "--pub", NULL);
    const char *fspub = opt(argc, argv, "--fspub", NULL);
    const char *anchor = opt(argc, argv, "--anchor", NULL);
    const char *sealfile = opt(argc, argv, "--seal-file", NULL);
    if (!dir) return usage();
    pqa_chain_state st;
    uint64_t bad = 0;
    int rc = pqa_segment_verify(dir, &st, &bad);
    if (rc != PQA_OK) {
        if (rc == PQA_ETAMPER)
            printf("VERIFY FAILED: chain broken at seq %llu\n", (unsigned long long)bad);
        return rc;
    }
    char hex[2 * PQA_HASH_LEN + 1];
    pqa_hex(st.head_hash, PQA_HASH_LEN, hex);
    printf("VERIFY OK: %llu entries\n  head: %s\n",
           (unsigned long long)st.count, hex);

    if (pub || fspub) {
        uint64_t seals = 0, covered = 0;
        int sr = pqa_seal_verify(dir, pub, fspub, anchor, sealfile, &seals, &covered);
        if (sr == PQA_OK)
            printf("SEALS OK: %llu seal(s), signed through seq %llu%s%s\n",
                   (unsigned long long)seals, (unsigned long long)covered,
                   fspub ? " (forward-secure)" : "",
                   sealfile ? " [off-box sink]" : "");
        else if (sr == PQA_ETAMPER)
            printf("SEALS FAILED: a seal did not verify\n");
        return sr;
    }
    return PQA_OK;
}

int main(int argc, char **argv)
{
    if (argc < 2) return usage();
    if (strcmp(argv[1], "init") == 0)    return cmd_init(argc, argv);
    if (strcmp(argv[1], "log") == 0)     return cmd_log(argc, argv);
    if (strcmp(argv[1], "keygen") == 0)  return cmd_keygen(argc, argv);
    if (strcmp(argv[1], "seal") == 0)    return cmd_seal(argc, argv);
    if (strcmp(argv[1], "verify") == 0)  return cmd_verify(argc, argv);
    if (strcmp(argv[1], "fs-init") == 0) return cmd_fs_init(argc, argv);
    if (strcmp(argv[1], "fs-advance") == 0) return cmd_fs_advance(argc, argv);
    if (strcmp(argv[1], "rotate") == 0)  return cmd_rotate(argc, argv);
    if (strcmp(argv[1], "proof") == 0)   return cmd_proof(argc, argv);
    if (strcmp(argv[1], "check-proof") == 0) return cmd_check_proof(argc, argv);
    if (strcmp(argv[1], "run") == 0)     return cmd_run(argc, argv);
    if (strcmp(argv[1], "version") == 0) { printf("pq-audit 1.0.0\n"); return PQA_OK; }
    return usage();
}
