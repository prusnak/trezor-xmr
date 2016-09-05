#ifndef __CRYPTO_XMR_H__
#define __CRYPTO_XMR_H__

#include <stdbool.h>
#include <stdint.h>

#include "limits-xmr.h"

#ifdef __cplusplus
extern "C" {
#endif

#define XMR_KEY_SIZE_BYTES		32U
#define XMR_KEY_SIZE_BITS		(XMR_KEY_SIZE_BYTES * 8)
#define XMR_HASH_SIZE			32U
#define XMR_HASH_STATE_SIZE		200U
#define XMR_MAX_STREAM_LENGTH	(32 + (XMR_MAX_MIXIN_COUNT * 64))
#define XMR_FINGERPRINT_LENGTH	4U

#define AES_IV_SIZE		16U
#define AES_KEY_SIZE 	32U

#pragma pack(push, 1)

typedef struct { uint8_t data[XMR_KEY_SIZE_BYTES]; } ec_point;
typedef struct { uint8_t data[XMR_KEY_SIZE_BYTES]; } ec_scalar;
typedef struct { ec_scalar c, r; } xmr_signature;
typedef struct { uint8_t data[XMR_HASH_SIZE]; } xmr_hash;

typedef ec_point xmr_derivation;
typedef ec_point xmr_pubkey;
typedef ec_point xmr_key_image;
typedef ec_scalar xmr_seckey;

#pragma pack(pop)

xmr_seckey xmr_generate_keys(xmr_pubkey *pubkey, xmr_seckey *seckey, const xmr_seckey *recovery_key, bool recover);
void xmr_generate_keys2(xmr_pubkey *pubkey, xmr_seckey *seckey);

void xmr_generate_keys_from_seed(const uint8_t *seed, size_t seedlen, const char *passphrase, xmr_seckey *viewkey,
	xmr_seckey *spendkey, void(*progress_callback)(uint32_t current, uint32_t total));

void xmr_public_key(const xmr_seckey *seckey, xmr_pubkey *pubkey);

void xmr_derivation_to_scalar(const xmr_derivation *derivation, size_t output_index, ec_scalar *res);
bool xmr_generate_key_derivation(const xmr_pubkey *pubkey, const xmr_seckey *seckey, xmr_derivation *derivation);
bool xmr_derive_public_key(const xmr_derivation *derivation, size_t output_index, const xmr_pubkey *base, xmr_pubkey *derived_key);
void xmr_derive_secret_key(const xmr_derivation *derivation, size_t output_index, const xmr_seckey *base, xmr_seckey *derived_key);
void xmr_derive_secret_key2(const ec_scalar *scalar, const xmr_seckey *base, xmr_seckey *derived_key);
bool xmr_check_pubkey_data(const uint8_t *data, size_t datalen);
void xmr_random_scalar(ec_scalar *scalar);

bool xmr_encrypt_data(const uint8_t *data, size_t datalen, const uint8_t *passphrase, size_t passlen, uint8_t *encrypted);
bool xmr_decrypt_data(const uint8_t *data, size_t datalen, const uint8_t *passphrase, size_t passlen, uint8_t *decrypted);
void xmr_pbkdf2_passphrase(const uint8_t *passphrase, size_t passlen, uint8_t *output);

void xmr_hash_to_scalar(const void *data, size_t length, ec_scalar *res);

void xmr_generate_key_image(const xmr_pubkey *pubkey, const xmr_seckey *seckey, xmr_key_image *key_image);
void xmr_generate_key_image2(const xmr_hash *hash, const xmr_seckey *seckey, xmr_key_image *key_image);

bool xmr_generate_ring_signature(const xmr_hash *prefix_hash, const xmr_key_image *key_image, const xmr_pubkey *pubs,
	size_t pubs_count, const xmr_seckey *seckey, size_t sec_index, xmr_signature *sig);
bool xmr_generate_ring_signature_stream(const xmr_hash *prefix_hash, const xmr_key_image *key_image, const xmr_pubkey *pubs,
	size_t pubs_count, size_t sec_index, uint8_t *buffer, size_t buffer_length, xmr_signature *sigs, ec_scalar *sum);
bool xmr_generate_ring_signature_cr(const xmr_pubkey *pubkey, const xmr_seckey *seckey, const ec_scalar *sum, const uint8_t *buffer,
	size_t buffer_length, xmr_signature *sig);
size_t xmr_get_stream_size(size_t pubs_count);

#ifdef __cplusplus
}
#endif

#endif
