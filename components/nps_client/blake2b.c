#include "blake2b.h"

#include <string.h>

typedef struct {
  uint64_t h[8];
  uint64_t t[2];
  uint8_t buf[128];
  size_t buflen;
  size_t outlen;
} nps_blake2b_ctx;

static const uint64_t blake2b_iv[8] = {
    UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)};

static const uint8_t blake2b_sigma[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};

static inline uint64_t rotr64(uint64_t x, unsigned n) {
  return (x >> n) | (x << (64 - n));
}

static inline uint64_t load64(const uint8_t *p) {
  uint64_t v = 0;
  for (unsigned i = 0; i < 8; i++)
    v |= (uint64_t) p[i] << (8 * i);
  return v;
}

static inline void store64(uint8_t *p, uint64_t v) {
  for (unsigned i = 0; i < 8; i++)
    p[i] = (uint8_t) (v >> (8 * i));
}

static void nps_blake2b_compress(nps_blake2b_ctx *ctx, const uint8_t block[128],
                                 int last) {
  uint64_t m[16], v[16];
  for (int i = 0; i < 16; i++)
    m[i] = load64(block + 8 * i);
  for (int i = 0; i < 8; i++)
    v[i] = ctx->h[i];
  v[8] = blake2b_iv[0];
  v[9] = blake2b_iv[1];
  v[10] = blake2b_iv[2];
  v[11] = blake2b_iv[3];
  v[12] = blake2b_iv[4] ^ ctx->t[0];
  v[13] = blake2b_iv[5] ^ ctx->t[1];
  v[14] = blake2b_iv[6] ^ (last ? ~UINT64_C(0) : 0);
  v[15] = blake2b_iv[7];

#define G(r, i, a, b, c, d)                                          \
  do {                                                               \
    a = a + b + m[blake2b_sigma[r][2 * i]];                          \
    d = rotr64(d ^ a, 32);                                           \
    c = c + d;                                                       \
    b = rotr64(b ^ c, 24);                                           \
    a = a + b + m[blake2b_sigma[r][2 * i + 1]];                      \
    d = rotr64(d ^ a, 16);                                           \
    c = c + d;                                                       \
    b = rotr64(b ^ c, 63);                                           \
  } while (0)

#define ROUND(r)                        \
  do {                                  \
    G(r, 0, v[0], v[4], v[8], v[12]);   \
    G(r, 1, v[1], v[5], v[9], v[13]);   \
    G(r, 2, v[2], v[6], v[10], v[14]);  \
    G(r, 3, v[3], v[7], v[11], v[15]);  \
    G(r, 4, v[0], v[5], v[10], v[15]);  \
    G(r, 5, v[1], v[6], v[11], v[12]);  \
    G(r, 6, v[2], v[7], v[8], v[13]);   \
    G(r, 7, v[3], v[4], v[9], v[14]);   \
  } while (0)

  for (int r = 0; r < 12; r++)
    ROUND(r);

#undef G
#undef ROUND

  for (int i = 0; i < 8; i++)
    ctx->h[i] ^= v[i] ^ v[i + 8];
}

static void nps_blake2b_init(nps_blake2b_ctx *ctx, size_t outlen) {
  memset(ctx, 0, sizeof(*ctx));
  ctx->outlen = outlen;
  uint8_t p[64];
  memset(p, 0, sizeof(p));
  // digest_length | key_length=0 | fanout=1 | depth=1
  p[0] = (uint8_t) outlen;
  p[2] = 1;
  p[3] = 1;
  for (int i = 0; i < 8; i++)
    ctx->h[i] = blake2b_iv[i] ^ load64(p + 8 * i);
}

static void nps_blake2b_update(nps_blake2b_ctx *ctx, const uint8_t *in,
                               size_t inlen) {
  while (inlen > 0) {
    if (ctx->buflen == 128) {
      uint64_t inc = (ctx->t[0] + 128) & UINT64_MAX;
      if (inc < ctx->t[0])
        ctx->t[1]++;
      ctx->t[0] = inc;
      nps_blake2b_compress(ctx, ctx->buf, 0);
      ctx->buflen = 0;
    }
    size_t take = 128 - ctx->buflen;
    if (take > inlen)
      take = inlen;
    memcpy(ctx->buf + ctx->buflen, in, take);
    ctx->buflen += take;
    in += take;
    inlen -= take;
  }
}

static void nps_blake2b_final(nps_blake2b_ctx *ctx, uint8_t *out) {
  uint64_t inc = (ctx->t[0] + ctx->buflen) & UINT64_MAX;
  if (inc < ctx->t[0])
    ctx->t[1]++;
  ctx->t[0] = inc;
  memset(ctx->buf + ctx->buflen, 0, 128 - ctx->buflen);
  nps_blake2b_compress(ctx, ctx->buf, 1);
  for (size_t i = 0; i < ctx->outlen; i++)
    out[i] = (uint8_t) (ctx->h[i / 8] >> (8 * (i % 8)));
}

int nps_blake2b_256(const uint8_t *input, size_t inlen, uint8_t out[32]) {
  if (out == NULL)
    return -1;
  nps_blake2b_ctx ctx;
  nps_blake2b_init(&ctx, 32);
  if (input != NULL && inlen > 0)
    nps_blake2b_update(&ctx, input, inlen);
  nps_blake2b_final(&ctx, out);
  return 0;
}
