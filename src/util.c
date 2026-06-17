/* util.c — hashing, time, atomic writes.  MIT (c) 2026 JFLC */
#define _POSIX_C_SOURCE 200809L
#include "pqaudit.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

int pqa_sha256(const void *data, size_t len, uint8_t out[PQA_HASH_LEN])
{
    unsigned int outlen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, data, len) == 1 &&
             EVP_DigestFinal_ex(ctx, out, &outlen) == 1 &&
             outlen == PQA_HASH_LEN;
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

void pqa_hex(const uint8_t *in, size_t len, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = d[in[i] >> 4];
        out[2 * i + 1] = d[in[i] & 0x0f];
    }
    out[2 * len] = '\0';
}

uint64_t pqa_now_realtime_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

uint64_t pqa_now_mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

int pqa_write_atomic(const char *path, const void *buf, size_t len, int mode)
{
    char tmp[4096];
    if (snprintf(tmp, sizeof tmp, "%s.tmp.%d", path, (int)getpid()) >= (int)sizeof tmp)
        return -1;

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return -1;

    const uint8_t *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n < 0) { close(fd); unlink(tmp); return -1; }
        off += (size_t)n;
    }
    if (fsync(fd) != 0) { close(fd); unlink(tmp); return -1; }
    if (close(fd) != 0) { unlink(tmp); return -1; }
    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}
