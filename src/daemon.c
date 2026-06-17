/* daemon.c — the `run` ingest daemon (M5).
 * MIT (c) 2026 Jean-Francois Lachance-Caumartin
 *
 * Accepts newline-delimited payloads (one entry per line, NDJSON in practice)
 * over a unix-domain socket, appends each to the hash chain, and auto-seals on
 * a count/time schedule.  SIGINT/SIGTERM trigger one final seal, then a clean
 * exit.  Single-threaded poll() loop; the signing key is unlocked once at
 * start-up (non-interactively) so no per-seal prompt is needed.
 */
#define _POSIX_C_SOURCE 200809L
#include "pqaudit.h"
#include "seal_internal.h"
#include "fs_internal.h"
#include "pqsign.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define MAX_CLIENTS  64
#define MAX_LINE     (1u << 20)   /* 1 MiB cap per line */

static volatile sig_atomic_t g_stop = 0;
static int g_sigpipe[2] = { -1, -1 };

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
    if (g_sigpipe[1] >= 0) { ssize_t r = write(g_sigpipe[1], "x", 1); (void)r; }
}

struct client { int fd; uint8_t *buf; size_t len, cap; };

/* Seal now (quietly — a daemon logs to stderr, not stdout).  Ring mode
 * re-reads the ring each time to honour the current epoch; key mode uses the
 * pre-loaded secret. */
static int do_seal(const pqa_run_opts *o, const pqsign_key *sk, uint64_t n)
{
    int rc;
    uint64_t epoch = 0;
    if (o->ringpath) {
        pqsign_key rk; uint32_t ep;
        if (pqa_ring_current(o->ringpath, &rk, &ep) != PQA_OK) return PQA_EUSAGE;
        epoch = ep;
        rc = pqa_seal_with_key(o->dir, &rk, ep, 0, o->sinks, o->n_sinks);
        key_free(&rk);
    } else {
        rc = pqa_seal_with_key(o->dir, sk, 0, 0, o->sinks, o->n_sinks);
    }
    if (rc == PQA_OK)
        fprintf(stderr, "pq-audit: sealed %llu entr%s (key_epoch %llu)\n",
                (unsigned long long)n, n == 1 ? "y" : "ies", (unsigned long long)epoch);
    return rc;
}

/* Consume complete lines from a client buffer, appending each as an entry.
 * Returns -1 if the client must be dropped (overflow / append error). */
static int drain_lines(struct client *c, const pqa_run_opts *o,
                       uint64_t *unsealed, uint64_t *seg_entries)
{
    size_t start = 0;
    for (;;) {
        uint8_t *nl = memchr(c->buf + start, '\n', c->len - start);
        if (!nl) break;
        size_t line_len = (size_t)(nl - (c->buf + start));
        if (line_len > 0) {
            if (pqa_segment_append(o->dir, o->src_id, 0, c->buf + start, (uint32_t)line_len, NULL, NULL) != PQA_OK)
                return -1;
            (*unsealed)++;
            (*seg_entries)++;
        }
        start = (size_t)(nl - c->buf) + 1;
    }
    /* shift the unconsumed tail to the front */
    if (start) { memmove(c->buf, c->buf + start, c->len - start); c->len -= start; }
    if (c->len > MAX_LINE) return -1;   /* a single oversized line */
    return 0;
}

static void client_close(struct client *c)
{
    if (c->fd >= 0) close(c->fd);
    free(c->buf);
    c->fd = -1; c->buf = NULL; c->len = c->cap = 0;
}

int pqa_run(const pqa_run_opts *o)
{
    /* Unlock the signing key up front (key mode); ring mode loads per-seal. */
    pqsign_key sk; memset(&sk, 0, sizeof sk);
    int have_key = 0;
    if (!o->ringpath) {
        if (pqa_key_load_pass(o->keypath, o->passphrase, &sk) != PQA_OK) return PQA_EUSAGE;
        have_key = 1;
    } else {
        /* validate the ring is usable before we start accepting traffic */
        pqsign_key probe; uint32_t ep;
        if (pqa_ring_current(o->ringpath, &probe, &ep) != PQA_OK) return PQA_EUSAGE;
        key_free(&probe);
    }

    int rc = PQA_EUSAGE;
    if (pipe(g_sigpipe) != 0) { perror("pipe"); goto out_key; }
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lfd < 0) { perror("socket"); goto out_pipe; }
    struct sockaddr_un addr; memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    if (strlen(o->socket_path) >= sizeof addr.sun_path) { fprintf(stderr, "pq-audit: socket path too long\n"); close(lfd); goto out_pipe; }
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", o->socket_path);
    unlink(o->socket_path);                       /* clear a stale socket */
    if (bind(lfd, (struct sockaddr *)&addr, sizeof addr) != 0) { perror("bind"); close(lfd); goto out_pipe; }
    if (listen(lfd, 16) != 0) { perror("listen"); close(lfd); unlink(o->socket_path); goto out_pipe; }

    fprintf(stderr, "pq-audit: listening on %s (dir=%s, src=%u, seal-every=%llu, seal-interval=%llus)\n",
            o->socket_path, o->dir, o->src_id,
            (unsigned long long)o->seal_every, (unsigned long long)o->seal_interval);

    struct client clients[MAX_CLIENTS];
    for (int i = 0; i < MAX_CLIENTS; i++) clients[i].fd = -1;

    uint64_t unsealed = 0;
    uint64_t last_seal_ns = pqa_now_mono_ns();
    uint64_t seg_entries = 0;
    if (pqa_segment_active_count(o->dir, &seg_entries) != PQA_OK) seg_entries = 0;

    while (!g_stop) {
        struct pollfd pfd[2 + MAX_CLIENTS];
        pfd[0].fd = g_sigpipe[0]; pfd[0].events = POLLIN;
        pfd[1].fd = lfd;          pfd[1].events = POLLIN;
        int n = 2;
        int slot_of[MAX_CLIENTS];
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].fd >= 0) { pfd[n].fd = clients[i].fd; pfd[n].events = POLLIN; slot_of[n] = i; n++; }
        }

        int timeout = -1;
        if (o->seal_interval) {
            uint64_t due = last_seal_ns + o->seal_interval * 1000000000ull;
            uint64_t now = pqa_now_mono_ns();
            timeout = now >= due ? 0 : (int)((due - now) / 1000000ull);
        }

        int pr = poll(pfd, (nfds_t)n, timeout);
        if (pr < 0) { if (errno == EINTR) continue; perror("poll"); break; }

        if (pfd[0].revents & POLLIN) break;        /* signalled */

        if (pfd[1].revents & POLLIN) {
            int cfd = accept(lfd, NULL, NULL);
            if (cfd >= 0) {
                int placed = 0;
                for (int i = 0; i < MAX_CLIENTS; i++)
                    if (clients[i].fd < 0) { clients[i].fd = cfd; clients[i].buf = NULL; clients[i].len = clients[i].cap = 0; placed = 1; break; }
                if (!placed) close(cfd);            /* table full */
            }
        }

        for (int k = 2; k < n; k++) {
            if (!(pfd[k].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            struct client *c = &clients[slot_of[k]];
            uint8_t tmp[8192];
            ssize_t got = recv(c->fd, tmp, sizeof tmp, 0);
            if (got <= 0) { client_close(c); continue; }
            if (c->len + (size_t)got > c->cap) {
                size_t nc = c->cap ? c->cap : 8192;
                while (nc < c->len + (size_t)got) nc *= 2;
                uint8_t *nb = realloc(c->buf, nc);
                if (!nb) { client_close(c); continue; }
                c->buf = nb; c->cap = nc;
            }
            memcpy(c->buf + c->len, tmp, (size_t)got);
            c->len += (size_t)got;
            if (drain_lines(c, o, &unsealed, &seg_entries) != 0) { client_close(c); continue; }

            if (o->seal_every && unsealed >= o->seal_every) {
                if (do_seal(o, &sk, unsealed) == PQA_OK) { unsealed = 0; last_seal_ns = pqa_now_mono_ns(); }
            }
            if (o->max_entries && seg_entries >= o->max_entries) {
                /* seal the boundary, then roll to a fresh segment */
                if (unsealed > 0 && do_seal(o, &sk, unsealed) == PQA_OK) { unsealed = 0; last_seal_ns = pqa_now_mono_ns(); }
                unsigned ni;
                if (pqa_segment_rotate(o->dir, &ni) == PQA_OK) {
                    fprintf(stderr, "pq-audit: rotated to segment %u after %llu entries\n", ni, (unsigned long long)seg_entries);
                    seg_entries = 0;
                }
            }
        }

        if (o->seal_interval && unsealed > 0) {
            uint64_t now = pqa_now_mono_ns();
            if (now - last_seal_ns >= o->seal_interval * 1000000000ull) {
                if (do_seal(o, &sk, unsealed) == PQA_OK) { unsealed = 0; last_seal_ns = now; }
            }
        }
    }

    fprintf(stderr, "pq-audit: shutting down");
    if (unsealed > 0) {
        fprintf(stderr, " — sealing %llu unsealed entr%s\n", (unsigned long long)unsealed, unsealed == 1 ? "y" : "ies");
        do_seal(o, &sk, unsealed);
    } else {
        fprintf(stderr, " — nothing unsealed\n");
    }
    for (int i = 0; i < MAX_CLIENTS; i++) if (clients[i].fd >= 0) client_close(&clients[i]);
    close(lfd);
    unlink(o->socket_path);
    rc = PQA_OK;

out_pipe:
    if (g_sigpipe[0] >= 0) close(g_sigpipe[0]);
    if (g_sigpipe[1] >= 0) close(g_sigpipe[1]);
out_key:
    if (have_key) key_free(&sk);
    return rc;
}
