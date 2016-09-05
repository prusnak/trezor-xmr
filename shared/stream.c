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

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "stream.h"
#include "keccak.h"

#include "base58.h"
#include <assert.h>

#define ENCRYPTED_PAYMENT_ID_TAIL 0x8d
#define ENCRYPTED_ID_SIZE		  8U

////////////////////////////////////////////////////////////////////////////////
// b58 address encoder taken (from cryptonote)

static const char b58_alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const size_t b58_encoded_block_sizes[] = {0, 2, 3, 5, 6, 7, 9, 10, 11};

#define B58_ALPHABET_SIZE 				58U
#define B58_FULL_BLOCK_SIZE 			8U
#define B58_ENCODED_FULL_BLOCK_SIZE 	11U

uint64_t uint_8be_to_64(const uint8_t *data, size_t size)
{
	assert(1 <= size && size <= sizeof(uint64_t));

	uint64_t res = 0;
	switch (9 - size)
	{
	case 1:            res |= *data++;
	case 2: res <<= 8; res |= *data++;
	case 3: res <<= 8; res |= *data++;
	case 4: res <<= 8; res |= *data++;
	case 5: res <<= 8; res |= *data++;
	case 6: res <<= 8; res |= *data++;
	case 7: res <<= 8; res |= *data++;
	case 8: res <<= 8; res |= *data; break;
	default: assert(false);
	}

	return res;
}

void b58_encode_block(const uint8_t *block, size_t size, char *res)
{
	assert(1 <= size && size <= B58_FULL_BLOCK_SIZE);
	uint64_t num = uint_8be_to_64((uint8_t *) block, size);
	size_t i = b58_encoded_block_sizes[size] - 1;
	while (0 < num)
	{
		uint64_t remainder = num % B58_ALPHABET_SIZE;
		num /= B58_ALPHABET_SIZE;
		res[i] = b58_alphabet[remainder];
		--i;

	}
}

void b58_encode(const uint8_t *data, size_t datalen, char *encoded)
{
	size_t block_count = datalen / B58_FULL_BLOCK_SIZE;
	size_t last_block_size = datalen % B58_FULL_BLOCK_SIZE;
	size_t res_size = block_count * B58_ENCODED_FULL_BLOCK_SIZE + b58_encoded_block_sizes[last_block_size];

	memset(encoded, b58_alphabet[0], res_size);

	for (size_t i = 0; i < block_count; i++)
	{
		b58_encode_block(data + i * B58_FULL_BLOCK_SIZE, B58_FULL_BLOCK_SIZE,
				&encoded[i * B58_ENCODED_FULL_BLOCK_SIZE]);

	}

	if (0 < last_block_size)
	{
		b58_encode_block(data +  block_count * B58_FULL_BLOCK_SIZE, last_block_size,
				&encoded[block_count * B58_ENCODED_FULL_BLOCK_SIZE]);
	}

	encoded[res_size] = '\0';
}

///////////////////////////////////////////////////////////////////////////////
// stream related xmr functions
void xmr_encode_varint(uint64_t value, uint8_t **ptr, size_t *incount)
{
	uint8_t *p = *ptr;
	size_t count = 1;
    while (value >= 0x80)
	{
        *p++ = ((uint8_t)(value & 0x7F)) | 0x80;
        value >>= 7;
        ++count;
    }

	*p++ = ((uint8_t)value) & 0x7F;
	*ptr += count;
	*incount += count;
}

static bool encrypt_payment_id(const xmr_pubkey *pubkey, const xmr_seckey *seckey, uint8_t *payment_id)
{
	xmr_derivation derivation;
	xmr_hash hash;
	uint8_t data[sizeof(derivation.data) + 1];

	if (!xmr_generate_key_derivation(pubkey, seckey, &derivation))
		return false;

	memcpy(data, derivation.data, sizeof(derivation.data));
	data[sizeof(derivation.data)] = ENCRYPTED_PAYMENT_ID_TAIL;
	keccak(data, sizeof(data), hash.data, sizeof(hash.data));

	for (size_t i = 0; i < 8; i++)
		payment_id[i] ^= hash.data[i];

	return true;
}

void xmr_add_tx_pubkey_to_extra(const xmr_pubkey *tx_pubkey, uint8_t *extra, size_t *count)
{
	extra[(*count)++] = TX_EXTRA_TAG_PUBKEY;
	memcpy(extra + *count, tx_pubkey->data, sizeof(tx_pubkey->data));
	*count += sizeof(tx_pubkey->data);
}

void xmr_add_payment_id_to_extra(const uint8_t *payment_id, size_t payment_id_size,
		const xmr_pubkey *pubkey, const xmr_seckey *seckey, uint8_t *extra, size_t *count)
{
	bool encrypted = payment_id_size == ENCRYPTED_ID_SIZE;

	extra[(*count)++] = TX_EXTRA_NONCE;
	uint8_t sz = encrypted ? 0x09 : 0x21;
	extra[(*count)++] = sz;
	extra[(*count)++] = encrypted ? TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID : TX_EXTRA_NONCE_PAYMENT_ID;
	if(encrypted)
	{
		uint8_t final[ENCRYPTED_ID_SIZE];
		memcpy(final, payment_id, ENCRYPTED_ID_SIZE);
		encrypt_payment_id(pubkey, seckey, final);
		for(size_t i = *count; i < *count + sz - 1; i++)
			extra[i] = final[i - *count];
	}
	else
	{
		for(size_t i = *count; i < *count + sz - 1; i++)
			extra[i] = payment_id[i - *count];
	}

	*count += sz - 1;
}

bool xmr_get_b58_address(bool integrated, bool testnet, const xmr_address *address, const xmr_hash *payment_id, char *encoded_addr)
{
	uint8_t buffer[256];
	size_t len = 0;

	uint8_t tag;

	if(integrated)
		tag = testnet ? XMR_TESTNET_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX : XMR_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
	else
		tag = testnet ? XMR_TESTNET_PUBLIC_ADDRESS_BASE58_PREFIX : XMR_PUBLIC_ADDRESS_BASE58_PREFIX;

	uint8_t *p = buffer;
	xmr_encode_varint(tag, &p, &len);

	memcpy(buffer + len, address->spendkey.data, sizeof(address->spendkey.data));
	len += sizeof(address->spendkey.data);
	memcpy(buffer + len, address->viewkey.data, sizeof(address->viewkey.data));
	len += sizeof(address->viewkey.data);

	if(integrated)
	{
		memcpy(buffer + len, payment_id, XMR_ENCRYPTED_PAYMENT_ID_SIZE);
		len += XMR_ENCRYPTED_PAYMENT_ID_SIZE;
	}

	xmr_hash checksum;
	keccak(buffer, len, checksum.data, sizeof(checksum.data));
	memcpy(buffer + len, checksum.data, XMR_ADDRESS_CHECKSUM_SIZE);
	len += XMR_ADDRESS_CHECKSUM_SIZE;
	b58_encode(buffer, len, encoded_addr);

	return true;
}
