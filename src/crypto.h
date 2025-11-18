#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define SHA512_DIGEST_LENGTH 64

typedef struct {
    uint64_t h[8];
    uint8_t buffer[128];
    uint64_t bitlen_hi;
    uint64_t bitlen_lo;
    size_t buffer_len;
} sha512_ctx;

void sha512_init(sha512_ctx *ctx);
void sha512_update(sha512_ctx *ctx, const uint8_t *data, size_t len);
void sha512_final(sha512_ctx *ctx, uint8_t out[SHA512_DIGEST_LENGTH]);

void hmac_sha512(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[SHA512_DIGEST_LENGTH]);

// HKDF (RFC 5869) using HMAC-SHA512
// out_len can be up to 255 * SHA512_DIGEST_LENGTH
int hkdf_sha512(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *out, size_t out_len);

// Derive a 256-byte one-way encryption output (hex-encoded later) from message and key material
// Uses HMAC-SHA512 in counter mode keyed by hkdf-expanded key to produce 256 bytes
int derive_one_way_output(const uint8_t *message, size_t message_len,
                          const uint8_t *password, size_t password_len,
                          const uint8_t *salt, size_t salt_len,
                          uint8_t out[256]);

void bytes_to_hex(const uint8_t *in, size_t len, char *out_hex); // out_hex must be 2*len+1

#endif // CRYPTO_H
