// Copyright (c) 2016, The Monero Project
//
// Author: NoodleDoodle
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <assert.h>
#include <stdint.h>
#include <memory.h>
#include <string.h>
#include <stdio.h>

#include "crypto-ops.h"
#include "crypto-xmr.h"
#include "aes.h"
#include "bip39.h"
#include "pbkdf2.h"
#include "keccak.h"
#if !defined(__arm__)
#include "random.h"
#endif

#if defined(GENKEYS2_HASH_SCALAR)
#include "sha512.h"
#endif

#if defined(__arm__)
#define NO_COPY_ON_WRITE
#include <alloca.h>
#include "../rng.h"
#else
static void random_buffer(void *result, size_t n)
{
    // Note: you can use your own rng here.
	generate_random_bytes_not_thread_safe(n, result);
}
#endif

#define copy_data(a, b) memcpy((a).data, (b).data, sizeof((a).data))

#pragma pack(push, 1)
typedef struct
{
	ec_point a, b;
} ec_point_pair_t;

typedef struct rs_comm_t
{
    xmr_hash h;
    ec_point_pair_t ab[];
} rs_comm;

#pragma pack(pop)

///////////////////////////////////////////////////////////////////////////////////
// Helper function
static inline size_t rs_comm_size(size_t pubs_count)
{
    return sizeof(rs_comm) + pubs_count * sizeof(ec_point_pair_t);
}

size_t xmr_get_stream_size(size_t pubs_count)
{
    return rs_comm_size(pubs_count);
}

static char *write_varint(char *dest, size_t i)
{
    while (i >= 0x80)
    {
        *dest = ((char)i & 0x7FL) | 0x80;
        ++dest;
        i >>= 7;
    }

    *dest = (char)i;
    ++dest;

    return dest;
}

static void derivation_to_scalar(const xmr_derivation *derivation, size_t output_index, ec_scalar *res)
{
#pragma pack(push, 1)
    struct
    {
        xmr_derivation derivation;
        char output_index[(sizeof(size_t) * 8 + 6) / 7];
    } buf;
#pragma pack(pop)

    copy_data(buf.derivation, *derivation);
    char *end = write_varint(buf.output_index, output_index);
    assert(end <= buf.output_index + sizeof(buf.output_index));
    xmr_hash_to_scalar(&buf, end - ((char *)&buf), res);
}

static void hash_to_ec(const xmr_pubkey *pubkey, ge_p3 *res)
{
    uint8_t hash[XMR_KEY_SIZE_BYTES];
    ge_p2 point;
    ge_p1p1 point2;

    keccak(pubkey->data, sizeof(pubkey->data), hash, sizeof(hash));
    ge_fromfe_frombytes_vartime(&point, hash);
    ge_mul8(&point2, &point);
    ge_p1p1_to_p3(res, &point2);
}

static void hash_to_ec2(const xmr_hash *hash, ge_p3 *res)
{
    ge_p2 point;
    ge_p1p1 point2;

    ge_fromfe_frombytes_vartime(&point, hash->data);
    ge_mul8(&point2, &point);
    ge_p1p1_to_p3(res, &point2);
}

///////////////////////////////////////////////////////////////////////////////////////
// Exports
void xmr_derivation_to_scalar(const xmr_derivation *derivation, size_t output_index, ec_scalar *res)
{
    derivation_to_scalar(derivation, output_index, res);
}

bool xmr_generate_key_derivation(const xmr_pubkey *key1, const xmr_seckey *key2, xmr_derivation *derivation)
{
    ge_p3 point;
    ge_p2 point2;
    ge_p1p1 point3;

    if (ge_frombytes_vartime(&point, key1->data) != 0)
        return false;

    ge_scalarmult(&point2, key2->data, &point);
    ge_mul8(&point3, &point2);
    ge_p1p1_to_p2(&point2, &point3);
    ge_tobytes(derivation->data, &point2);

    return true;
}

void xmr_hash_to_scalar(const void *data, size_t length, ec_scalar *res)
{
    keccak(data, length, res->data, sizeof(res->data));
    sc_reduce32(res->data);
}

void xmr_random_scalar(ec_scalar *scalar)
{
    unsigned char tmp[64];
    random_buffer(tmp, 64);
    sc_reduce(tmp);
    memcpy(scalar->data, tmp, 32);
}

xmr_seckey xmr_generate_keys(xmr_pubkey *pubkey, xmr_seckey *seckey, const xmr_seckey *rkey, bool recover)
{
    ge_p3 point;

    ec_scalar rng;
    if (recover)
        copy_data(rng, *rkey);
    else
        xmr_random_scalar(&rng);

    copy_data(*seckey, rng);
    sc_reduce32(seckey->data);  // reduce in case second round of keys (sendkeys)

    ge_scalarmult_base(&point, seckey->data);
    ge_p3_tobytes(pubkey->data, &point);

    return rng;
}

void xmr_generate_keys2(xmr_pubkey *pubkey, xmr_seckey *seckey)
{
    ge_p3 point;
    ec_scalar rng;
    xmr_random_scalar(&rng);

#if defined(GENKEYS2_HASH_SCALAR)
    uint8_t tmp[64];
    sha512(rng.data, 32, tmp);
    memcpy(rng.data, tmp, 32);
#endif

    rng.data[0] &= 248;
    rng.data[31] &= 63;
    rng.data[31] |= 64;
    copy_data(*seckey, rng);

    ge_scalarmult_base(&point, seckey->data);
    ge_p3_tobytes(pubkey->data, &point);
}

bool xmr_derive_public_key(const xmr_derivation *derivation, size_t output_index, const xmr_pubkey *base, xmr_pubkey *derived_key)
{
    ec_scalar scalar;
    ge_p3 point1;
    ge_p3 point2;
    ge_cached point3;
    ge_p1p1 point4;
    ge_p2 point5;
    if (ge_frombytes_vartime(&point1, base->data) != 0)
        return false;

    derivation_to_scalar(derivation, output_index, &scalar);
    ge_scalarmult_base(&point2, scalar.data);
    ge_p3_to_cached(&point3, &point2);
    ge_add(&point4, &point1, &point3);
    ge_p1p1_to_p2(&point5, &point4);
    ge_tobytes(derived_key->data, &point5);

    return true;
}

void xmr_derive_secret_key(const xmr_derivation *derivation, size_t output_index, const xmr_seckey *base, xmr_seckey *derived_key)
{
    ec_scalar scalar;
    assert(sc_check(base->data) == 0);
    derivation_to_scalar(derivation, output_index, &scalar);
    sc_add(derived_key->data, base->data, scalar.data);
}

void xmr_derive_secret_key2(const ec_scalar *scalar, const xmr_seckey *base, xmr_seckey *derived_key)
{
    assert(sc_check(base->data) == 0);
    sc_add(derived_key->data, base->data, scalar->data);
}

bool xmr_check_pubkey_data(const uint8_t *data, size_t datalen)
{
    ge_p3 point;

    if (datalen != XMR_KEY_SIZE_BYTES)
        return false;

    return ge_frombytes_vartime(&point, data) == 0;
}

#define AES_96BIT_NONCE

#if defined(AES_96BIT_NONCE)
#define AES_NONCE_SIZE  12
#else
#define AES_NONCE_SIZE  8
#endif

static void ctr_inc(unsigned char *ctr_blk)
{
    uint32_t c;

    c = *(uint32_t*)(ctr_blk + AES_NONCE_SIZE);
    c++;
    *(uint32_t*)(ctr_blk + AES_NONCE_SIZE) = c;

#if !defined(AES_96BIT_NONCE)
    if (!c)
        *(uint32_t*)(ctr_blk + 12) = *(uint32_t*)(ctr_blk + 12) + 1;
#endif
}

bool xmr_decrypt_data(const uint8_t *data, size_t datalen, const uint8_t *passphrase, size_t passlen, uint8_t *decrypted)
{
#if defined(DISABLE_AES)
    memcpy(decrypted, data, datalen);
#else
    uint8_t key[64];
    uint8_t salt[12];

    aes_encrypt_ctx ctx;

    if (passlen < 48)
    	return false;
    if (passlen > 48)
    	passlen = 48;

    memcpy(key, passphrase, 48);

#if defined(NO_COPY_ON_WRITE)
    uint8_t *tmp = decrypted;
#else
    uint8_t *tmp = (uint8_t *)malloc(datalen);
#endif

    aes_encrypt_key256(key, &ctx);
    aes_mode_reset(&ctx);

    uint8_t ctr_blk[AES_IV_SIZE];
    memset(ctr_blk, 0, sizeof(ctr_blk));
    memcpy(ctr_blk, key + 32, AES_NONCE_SIZE);

    aes_ctr_decrypt(data, tmp, datalen, ctr_blk, ctr_inc, &ctx);

#if !defined(NO_COPY_ON_WRITE)
    memcpy(decrypted, tmp, datalen);
    memset(tmp, 0, datalen);
    free(tmp);
#endif

    memset(key, 0, sizeof(key));
    memset(salt, 0, sizeof(salt));
    memset(&ctx, 0, sizeof(ctx));
#endif

    return true;
}

bool xmr_encrypt_data(const uint8_t *data, size_t datalen, const uint8_t *passphrase, size_t passlen, uint8_t *encrypted)
{
#if defined(DISABLE_AES)
    memcpy(encrypted, data, datalen);
#else
    uint8_t key[64];
    uint8_t salt[12];

    aes_encrypt_ctx ctx;

    if (passlen < 48)
    	return false;
    if (passlen > 48)
    	passlen = 48;

    memcpy(key, passphrase, 48);

#if defined(NO_COPY_ON_WRITE)
    uint8_t *tmp = encrypted;
#else
    uint8_t *tmp = (uint8_t *)malloc(datalen);
#endif

    aes_encrypt_key256(key, &ctx);
    aes_mode_reset(&ctx);

    uint8_t ctr_blk[AES_IV_SIZE];
    memset(ctr_blk, 0, sizeof(ctr_blk));
    memcpy(ctr_blk, key + 32, AES_NONCE_SIZE);

    aes_ctr_encrypt(data, tmp, datalen, ctr_blk, ctr_inc, &ctx);
    //aes_cbc_encrypt(data, tmp, datalen, key + 32, &ctx);

#if !defined(NO_COPY_ON_WRITE)
    memcpy(encrypted, tmp, datalen);
    memset(tmp, 0, datalen);

#if defined(_DEBUG)
    memset(ctr_blk, 0, sizeof(ctr_blk));
    memcpy(ctr_blk, key + 32, AES_NONCE_SIZE);
    aes_mode_reset(&ctx);
    uint8_t *data2 = (uint8_t *)malloc(datalen);
    aes_ctr_decrypt(encrypted, data2, datalen, ctr_blk, ctr_inc, &ctx);
    bool equal = memcmp(data, data2, datalen) == 0;
    free(data2);
    assert(equal);
#endif
    free(tmp);
#endif

    memset(key, 0, sizeof(key));
    memset(salt, 0, sizeof(salt));
    memset(&ctx, 0, sizeof(ctx));
#endif

    return true;
}

void xmr_generate_keys_from_seed(const uint8_t *seed, size_t seedlen, const char *passphrase, xmr_seckey *viewkey,
    xmr_seckey *spendkey, void(*progress_callback)(uint32_t current, uint32_t total))
{
    uint8_t seed32[32];
    uint8_t seed64[64];

    memset(seed32, 0, sizeof(seed32));
    memcpy(seed32, seed, seedlen <= sizeof(seed32) ? seedlen : sizeof(seed32));
    // 1. node->private_key -> seed
    keccak(seed32, sizeof(seed32), seed32, sizeof(seed32));

    // TODO: This is just reworking the node::private_key into a spendkey.
    // Can be modified or replaced altogether.
    if(passphrase != NULL && strlen(passphrase))
    {
    	// Note: setting a passphrase for each node is allowed
        // 2. seed || passphrase -> seed64
    	PBKDF2_HMAC_SHA512_CTX pctx;
		pbkdf2_hmac_sha512_Init(&pctx, (const uint8_t *)seed32, sizeof(seed32), (const uint8_t *) "vsmothra", 8);
		if(progress_callback)
        {
			progress_callback(0, BIP39_PBKDF2_ROUNDS);
        }
        	
		for (int i = 0; i < 8; i++)
		{
			pbkdf2_hmac_sha512_Update(&pctx, BIP39_PBKDF2_ROUNDS / 8);
			if(progress_callback)
			{
				progress_callback((i + 1) * BIP39_PBKDF2_ROUNDS / 8, BIP39_PBKDF2_ROUNDS);
			}
		}
		pbkdf2_hmac_sha512_Final(&pctx, seed64);
		
        // 3. use seed64 to create a "random" scalar
        keccak(seed64, sizeof(seed64), seed64, sizeof(seed64));
        sc_reduce(seed64);
        memcpy(spendkey->data, seed64, 32);
    }
    else
    {
        sc_reduce32(seed32);
        memcpy(spendkey->data, seed32, 32);
    }

    // 4. deterministically create viewkey from spendkey
    keccak(spendkey->data, sizeof(spendkey->data), viewkey->data, sizeof(viewkey->data));
    sc_reduce32(viewkey->data);
}

void xmr_public_key(const xmr_seckey *seckey, xmr_pubkey *pubkey)
{
    xmr_seckey dummy;
    xmr_generate_keys(pubkey, &dummy, seckey, true);
}

void xmr_generate_key_image(const xmr_pubkey *pubkey, const xmr_seckey *seckey, xmr_key_image *key_image)
{
    ge_p3 point;
    ge_p2 point2;
    assert(sc_check(seckey->data) == 0);
    hash_to_ec(pubkey, &point);
    ge_scalarmult(&point2, seckey->data, &point);
    ge_tobytes(key_image->data, &point2);
}

void xmr_generate_key_image2(const xmr_hash *hash, const xmr_seckey *seckey, xmr_key_image *key_image)
{
    ge_p3 point;
    ge_p2 point2;
    assert(sc_check(seckey->data) == 0);
    
    hash_to_ec2(hash, &point);
    
    ge_scalarmult(&point2, seckey->data, &point);
    ge_tobytes(key_image->data, &point2);
}

#if !defined(__arm__)
bool xmr_generate_ring_signature(const xmr_hash *prefix_hash, const xmr_key_image *key_image, const xmr_pubkey *pubs,
    size_t pubs_count, const xmr_seckey *seckey, size_t sec_index, xmr_signature *sig)
{
    size_t i;
    ge_p3 image_unp;
    ge_dsmp image_pre;
    ec_scalar sum, k, h;
    rs_comm *const buf = (rs_comm *const)alloca(rs_comm_size(pubs_count));
    assert(sec_index < pubs_count);

    if (ge_frombytes_vartime(&image_unp, key_image->data) != 0)
    {
        return false;
    }

    ge_dsm_precomp(image_pre, &image_unp);
    sc_0(sum.data);
    buf->h = *prefix_hash;
    for (i = 0; i < pubs_count; i++)
    {
        ge_p2 tmp2;
        ge_p3 tmp3;
        if (i == sec_index)
        {
            xmr_random_scalar(&k);
            ge_scalarmult_base(&tmp3, k.data);
            ge_p3_tobytes(buf->ab[i].a.data, &tmp3);
            hash_to_ec(&pubs[i], &tmp3);
            ge_scalarmult(&tmp2, k.data, &tmp3);
            ge_tobytes(buf->ab[i].b.data, &tmp2);
        }
        else
        {
            xmr_random_scalar(&sig[i].c);
            xmr_random_scalar(&sig[i].r);
            if (ge_frombytes_vartime(&tmp3, pubs[i].data) != 0)
            {
                return false;
            }
            ge_double_scalarmult_base_vartime(&tmp2, sig[i].c.data, &tmp3, sig[i].r.data);
            ge_tobytes(buf->ab[i].a.data, &tmp2);
            hash_to_ec(&pubs[i], &tmp3);
            ge_double_scalarmult_precomp_vartime(&tmp2, sig[i].r.data, &tmp3, sig[i].c.data, image_pre);
            ge_tobytes(buf->ab[i].b.data, &tmp2);
            sc_add(sum.data, sum.data, sig[i].c.data);
        }
    }
    xmr_hash_to_scalar(buf, rs_comm_size(pubs_count), &h);
    sc_sub(sig[sec_index].c.data, h.data, sum.data);
    sc_mulsub(sig[sec_index].r.data, sig[sec_index].c.data, seckey->data, k.data);
    return true;
}

bool xmr_generate_ring_signature_stream(const xmr_hash *prefix_hash, const xmr_key_image *key_image, const xmr_pubkey *pubs,
    size_t pubs_count, size_t sec_index, uint8_t *buffer, size_t buffer_length, xmr_signature *sigs, ec_scalar *sum)
{
    size_t i;
    ge_p3 image_unp;
    ge_dsmp image_pre;
    ec_scalar k, h;

    size_t actual_length = rs_comm_size(pubs_count);
    if (actual_length > buffer_length) // || actual_length > XMR_MAX_STREAM_LENGTH)
        return false;

    rs_comm *const buf = (rs_comm *const)buffer;
    assert(sec_index < pubs_count);

    memset(buffer, 0, buffer_length);

    if (ge_frombytes_vartime(&image_unp, key_image->data) != 0)
    {
        return false;
    }

    ge_dsm_precomp(image_pre, &image_unp);
    sc_0(sum->data);
    buf->h = *prefix_hash;
    for (i = 0; i < pubs_count; i++)
    {
        ge_p2 tmp2;
        ge_p3 tmp3;
        if (i == sec_index)
        {
#if defined(DEBUG_SIGNATURES)
            // do this dummy step so the test vectors align.
            xmr_random_scalar(&sigs[i].c);
#endif
            memset(sigs[i].c.data, 0, sizeof(sigs[i].c.data));
            memset(buf->ab[i].a.data, 0, sizeof(buf->ab[i].a.data));
            memset(buf->ab[i].b.data, 0, sizeof(buf->ab[i].b.data));
        }
        else
        {
            xmr_random_scalar(&sigs[i].c);
            xmr_random_scalar(&sigs[i].r);
            if (ge_frombytes_vartime(&tmp3, pubs[i].data) != 0)
            {
                return false;
            }
            ge_double_scalarmult_base_vartime(&tmp2, sigs[i].c.data, &tmp3, sigs[i].r.data);
            ge_tobytes(buf->ab[i].a.data, &tmp2);
            hash_to_ec(&pubs[i], &tmp3);
            ge_double_scalarmult_precomp_vartime(&tmp2, sigs[i].r.data, &tmp3, sigs[i].c.data, image_pre);
            ge_tobytes(buf->ab[i].b.data, &tmp2);
            sc_add(sum->data, sum->data, sigs[i].c.data);
        }
    }

    return true;
}

#endif

bool xmr_generate_ring_signature_cr(const xmr_pubkey *pubkey, const xmr_seckey *seckey, const ec_scalar *sum, const uint8_t *buffer, size_t buffer_length, xmr_signature *sig)
{
    size_t i;
    ec_scalar k, h;
    ge_p2 tmp2;
    ge_p3 tmp3;

    rs_comm *const buf = (rs_comm *const)buffer;

    uint8_t dummy[sizeof(ec_scalar) * 2];
    memset(dummy, 0, sizeof(dummy));

    size_t count = (buffer_length - sizeof(rs_comm)) / (sizeof(ec_scalar) * 2);

    size_t index;
    bool found = false;
    for (i = 0; i < count; i++)
    {
        if (memcmp(&buf->ab[i], dummy, sizeof(dummy)) == 0)
        {
            index = i;
            found = true;
            break;
        }
    }

    if (!found)
        return false;

#if DEBUG_LINK
    uint8_t tmp[] =
    {
        0xd4, 0x91, 0x98, 0x32, 0x06, 0xc1, 0x94, 0x77,
        0xa3, 0x69, 0xec, 0xd0, 0x2f, 0xda, 0xb5, 0x81,
        0x3c, 0x1a, 0xe2, 0xb8, 0x69, 0xbc, 0x48, 0xd1,
        0xa4, 0xfb, 0xee, 0x82, 0xe1, 0xd8, 0x5b, 0x89,
        0xcf, 0x6f, 0x6b, 0x69, 0x2e, 0x3c, 0x34, 0xa9,
        0x62, 0xbf, 0xe3, 0xa3, 0x64, 0x70, 0x4a, 0x78,
        0x4a, 0xaa, 0x95, 0x58, 0x54, 0x6a, 0x67, 0x04,
        0x20, 0x73, 0x22, 0x87, 0xb4, 0xc7, 0x5e, 0xc0
    };

    sc_reduce(tmp);
    memcpy(k.data, tmp, sizeof(k.data));
#else
    xmr_random_scalar(&k);
#endif

    ge_scalarmult_base(&tmp3, k.data);
    ge_p3_tobytes(buf->ab[index].a.data, &tmp3);
    hash_to_ec(pubkey, &tmp3);
    ge_scalarmult(&tmp2, k.data, &tmp3);
    ge_tobytes(buf->ab[index].b.data, &tmp2);

    xmr_hash_to_scalar(buf, rs_comm_size(count), &h);
    sc_sub(sig->c.data, h.data, sum->data);
    sc_mulsub(sig->r.data, sig->c.data, seckey->data, k.data);

    return true;
}
