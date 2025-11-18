#include "crypto.h"
#include <string.h>

#define ROTR64(x,n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHR(x,n) ((x) >> (n))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR64((x),28) ^ ROTR64((x),34) ^ ROTR64((x),39))
#define BSIG1(x) (ROTR64((x),14) ^ ROTR64((x),18) ^ ROTR64((x),41))
#define SSIG0(x) (ROTR64((x),1) ^ ROTR64((x),8) ^ SHR((x),7))
#define SSIG1(x) (ROTR64((x),19) ^ ROTR64((x),61) ^ SHR((x),6))

static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22c26ULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

static void sha512_transform(sha512_ctx *ctx, const uint8_t data[128]) {
    uint64_t w[80];
    for (size_t i = 0; i < 16; i++) {
        w[i] = ((uint64_t)data[i * 8 + 0] << 56) |
               ((uint64_t)data[i * 8 + 1] << 48) |
               ((uint64_t)data[i * 8 + 2] << 40) |
               ((uint64_t)data[i * 8 + 3] << 32) |
               ((uint64_t)data[i * 8 + 4] << 24) |
               ((uint64_t)data[i * 8 + 5] << 16) |
               ((uint64_t)data[i * 8 + 6] << 8) |
               ((uint64_t)data[i * 8 + 7]);
    }
    for (size_t i = 16; i < 80; i++) {
        w[i] = SSIG1(w[i-2]) + w[i-7] + SSIG0(w[i-15]) + w[i-16];
    }

    uint64_t a = ctx->h[0];
    uint64_t b = ctx->h[1];
    uint64_t c = ctx->h[2];
    uint64_t d = ctx->h[3];
    uint64_t e = ctx->h[4];
    uint64_t f = ctx->h[5];
    uint64_t g = ctx->h[6];
    uint64_t h = ctx->h[7];

    for (size_t i = 0; i < 80; i++) {
        uint64_t t1 = h + BSIG1(e) + CH(e, f, g) + K[i] + w[i];
        uint64_t t2 = BSIG0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;
}

void sha512_init(sha512_ctx *ctx) {
    ctx->h[0] = 0x6a09e667f3bcc908ULL;
    ctx->h[1] = 0xbb67ae8584caa73bULL;
    ctx->h[2] = 0x3c6ef372fe94f82bULL;
    ctx->h[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->h[4] = 0x510e527fade682d1ULL;
    ctx->h[5] = 0x9b05688c2b3e6c1fULL;
    ctx->h[6] = 0x1f83d9abfb41bd6bULL;
    ctx->h[7] = 0x5be0cd19137e2179ULL;
    ctx->bitlen_hi = 0;
    ctx->bitlen_lo = 0;
    ctx->buffer_len = 0;
}

static void sha512_add_bits(sha512_ctx *ctx, uint64_t bits) {
    ctx->bitlen_lo += bits;
    if (ctx->bitlen_lo < bits) {
        ctx->bitlen_hi++;
    }
}

void sha512_update(sha512_ctx *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;
    if (ctx->buffer_len) {
        while (i < len && ctx->buffer_len < 128) {
            ctx->buffer[ctx->buffer_len++] = data[i++];
        }
        if (ctx->buffer_len == 128) {
            sha512_transform(ctx, ctx->buffer);
            sha512_add_bits(ctx, 1024);
            ctx->buffer_len = 0;
        }
    }

    while (i + 128 <= len) {
        sha512_transform(ctx, data + i);
        sha512_add_bits(ctx, 1024);
        i += 128;
    }

    while (i < len) {
        ctx->buffer[ctx->buffer_len++] = data[i++];
    }
}

void sha512_final(sha512_ctx *ctx, uint8_t out[SHA512_DIGEST_LENGTH]) {
    sha512_add_bits(ctx, (uint64_t)ctx->buffer_len * 8ULL);

    // Pad
    ctx->buffer[ctx->buffer_len++] = 0x80;

    if (ctx->buffer_len > 112) {
        while (ctx->buffer_len < 128) ctx->buffer[ctx->buffer_len++] = 0x00;
        sha512_transform(ctx, ctx->buffer);
        ctx->buffer_len = 0;
    }

    while (ctx->buffer_len < 112) ctx->buffer[ctx->buffer_len++] = 0x00;

    // Append length (128-bit big endian)
    uint64_t hi = ctx->bitlen_hi;
    uint64_t lo = ctx->bitlen_lo;

    ctx->buffer[112] = (uint8_t)(hi >> 56);
    ctx->buffer[113] = (uint8_t)(hi >> 48);
    ctx->buffer[114] = (uint8_t)(hi >> 40);
    ctx->buffer[115] = (uint8_t)(hi >> 32);
    ctx->buffer[116] = (uint8_t)(hi >> 24);
    ctx->buffer[117] = (uint8_t)(hi >> 16);
    ctx->buffer[118] = (uint8_t)(hi >> 8);
    ctx->buffer[119] = (uint8_t)(hi);

    ctx->buffer[120] = (uint8_t)(lo >> 56);
    ctx->buffer[121] = (uint8_t)(lo >> 48);
    ctx->buffer[122] = (uint8_t)(lo >> 40);
    ctx->buffer[123] = (uint8_t)(lo >> 32);
    ctx->buffer[124] = (uint8_t)(lo >> 24);
    ctx->buffer[125] = (uint8_t)(lo >> 16);
    ctx->buffer[126] = (uint8_t)(lo >> 8);
    ctx->buffer[127] = (uint8_t)(lo);

    sha512_transform(ctx, ctx->buffer);

    for (size_t i = 0; i < 8; i++) {
        out[i*8+0] = (uint8_t)(ctx->h[i] >> 56);
        out[i*8+1] = (uint8_t)(ctx->h[i] >> 48);
        out[i*8+2] = (uint8_t)(ctx->h[i] >> 40);
        out[i*8+3] = (uint8_t)(ctx->h[i] >> 32);
        out[i*8+4] = (uint8_t)(ctx->h[i] >> 24);
        out[i*8+5] = (uint8_t)(ctx->h[i] >> 16);
        out[i*8+6] = (uint8_t)(ctx->h[i] >> 8);
        out[i*8+7] = (uint8_t)(ctx->h[i]);
    }

    // Clear sensitive data in context
    memset(ctx, 0, sizeof(*ctx));
}

void hmac_sha512(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[SHA512_DIGEST_LENGTH]) {
    uint8_t k_ipad[128];
    uint8_t k_opad[128];
    uint8_t tk[SHA512_DIGEST_LENGTH];

    if (key_len > 128) {
        sha512_ctx tctx;
        sha512_init(&tctx);
        sha512_update(&tctx, key, key_len);
        sha512_final(&tctx, tk);
        key = tk;
        key_len = SHA512_DIGEST_LENGTH;
    }

    memset(k_ipad, 0x36, sizeof(k_ipad));
    memset(k_opad, 0x5c, sizeof(k_opad));

    for (size_t i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, k_ipad, sizeof(k_ipad));
    sha512_update(&ctx, data, data_len);
    sha512_final(&ctx, tk);

    sha512_init(&ctx);
    sha512_update(&ctx, k_opad, sizeof(k_opad));
    sha512_update(&ctx, tk, SHA512_DIGEST_LENGTH);
    sha512_final(&ctx, out);

    // Clear
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memset(tk, 0, sizeof(tk));
    memset(&ctx, 0, sizeof(ctx));
}

int hkdf_sha512(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *out, size_t out_len) {
    uint8_t prk[SHA512_DIGEST_LENGTH];
    // If salt is not provided, use zeros of HashLen
    uint8_t zeros[SHA512_DIGEST_LENGTH];
    if (salt == NULL || salt_len == 0) {
        memset(zeros, 0, sizeof(zeros));
        salt = zeros;
        salt_len = sizeof(zeros);
    }

    hmac_sha512(salt, salt_len, ikm, ikm_len, prk);

    size_t n = (out_len + SHA512_DIGEST_LENGTH - 1) / SHA512_DIGEST_LENGTH;
    if (n > 255) return -1;

    uint8_t t[SHA512_DIGEST_LENGTH];
    size_t t_len = 0;
    size_t pos = 0;

    for (size_t i = 1; i <= n; i++) {
        // T(i) = HMAC(PRK, T(i-1) | info | i)
        sha512_ctx ctx;
        uint8_t k_ipad[128];
        uint8_t k_opad[128];
        uint8_t tmp[SHA512_DIGEST_LENGTH];

        // Precompute pads for HMAC
        memset(k_ipad, 0x36, sizeof(k_ipad));
        memset(k_opad, 0x5c, sizeof(k_opad));
        for (size_t j = 0; j < SHA512_DIGEST_LENGTH; j++) {
            k_ipad[j] ^= prk[j];
            k_opad[j] ^= prk[j];
        }

        sha512_init(&ctx);
        sha512_update(&ctx, k_ipad, sizeof(k_ipad));
        if (t_len > 0) sha512_update(&ctx, t, t_len);
        if (info && info_len) sha512_update(&ctx, info, info_len);
        uint8_t c = (uint8_t)i;
        sha512_update(&ctx, &c, 1);
        sha512_final(&ctx, tmp);

        sha512_init(&ctx);
        sha512_update(&ctx, k_opad, sizeof(k_opad));
        sha512_update(&ctx, tmp, SHA512_DIGEST_LENGTH);
        sha512_final(&ctx, t);
        t_len = SHA512_DIGEST_LENGTH;

        size_t to_copy = (pos + t_len > out_len) ? (out_len - pos) : t_len;
        memcpy(out + pos, t, to_copy);
        pos += to_copy;

        // Clear temp
        memset(k_ipad, 0, sizeof(k_ipad));
        memset(k_opad, 0, sizeof(k_opad));
        memset(tmp, 0, sizeof(tmp));
        memset(&ctx, 0, sizeof(ctx));
    }

    memset(prk, 0, sizeof(prk));
    memset((void*)salt, 0, salt == zeros ? salt_len : 0); // avoid clearing caller salt
    memset(zeros, 0, sizeof(zeros));
    memset(t, 0, sizeof(t));

    return 0;
}

int derive_one_way_output(const uint8_t *message, size_t message_len,
                          const uint8_t *password, size_t password_len,
                          const uint8_t *salt, size_t salt_len,
                          uint8_t out[256]) {
    // Step 1: Hash the password with salt using HMAC to get IKM
    uint8_t ikm[SHA512_DIGEST_LENGTH];
    hmac_sha512(salt, salt_len, password, password_len, ikm);

    // Step 2: HKDF-expand to 64 bytes key material
    uint8_t okm[64];
    const uint8_t info[] = { 'e','n','c','r','y','p','t','o','r','-','v','1' };
    if (hkdf_sha512(salt, salt_len, ikm, sizeof(ikm), info, sizeof(info), okm, sizeof(okm)) != 0) {
        memset(ikm, 0, sizeof(ikm));
        return -1;
    }

    // Step 3: Produce 4 blocks of HMAC-SHA512 over message||counter
    uint8_t block[SHA512_DIGEST_LENGTH];
    size_t pos = 0;
    for (uint8_t counter = 1; counter <= 4; counter++) {
        // HMAC_SHA512(key=okm, data=message||counter)
        // Build data: message then 1-byte counter
        uint8_t last_byte = counter;
        // HMAC function consumes pointer+len; do two calls to avoid extra buffer
        // hmac_sha512 doesn't support streaming, so we need to assemble a buffer
        // For simplicity and to avoid large allocations, we copy into a temporary buffer if message_len is small
        // but to be safe, allocate on stack only for moderate sizes
        size_t tmp_len = message_len + 1;
        if (tmp_len > 4096) return -2; // guard against absurdly long input
        uint8_t tmp[4096];
        memcpy(tmp, message, message_len);
        tmp[message_len] = last_byte;
        hmac_sha512(okm, sizeof(okm), tmp, tmp_len, block);
        memcpy(out + pos, block, SHA512_DIGEST_LENGTH);
        pos += SHA512_DIGEST_LENGTH;
    }

    // Clear sensitive
    memset(ikm, 0, sizeof(ikm));
    memset(okm, 0, sizeof(okm));
    memset(block, 0, sizeof(block));

    return 0;
}

void bytes_to_hex(const uint8_t *in, size_t len, char *out_hex) {
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out_hex[2*i]   = hex[in[i] >> 4];
        out_hex[2*i+1] = hex[in[i] & 0x0f];
    }
    out_hex[2*len] = '\0';
}
