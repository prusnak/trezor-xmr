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

#include <algorithm>
#include <cstdio>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/filesystem.hpp>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "crypto/crypto.h"

#include "include_base_utils.h"
#include "misc_language.h"
#include "profile_tools.h"
#include "file_io_utils.h"

#include "bip39.h"
#include "bip32.h"
#include "aes.h"
#include "crypto-ops.h"
#include "crypto-xmr.h"

#include "hash-ops.h"
#include "stream.h"
#include "kokko.h"
#include "profile_tools.h"

#include "protobuf-c/types.pb-c.h"
#include "protobuf-c/protobuf-c.h"
#include "protobuf-c/messages.pb-c.h"
#include "protobuf-c/storage.pb-c.h"

#include "stream.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "keccak.h"
void setup_random(int c);
void generate_random_bytes_not_thread_safe(size_t n, void *result);

#ifdef __cplusplus
}
#endif

#if !defined(_countof)
#define _countof(_a) (sizeof(_a) / sizeof(_a[0]))
#endif

static void generate_random_bytes(size_t n, void *result)
{
	generate_random_bytes_not_thread_safe(n, result);
}

static uint8_t *fromhex(const char *str)
{
	static uint8_t buf[8192];
	uint8_t c;
	size_t i;
	for (i = 0; i < strlen(str) / 2; i++) 
	{
		c = 0;
		if (str[i*2] >= '0' && str[i*2] <= '9') c += (str[i*2] - '0') << 4;
		if (str[i*2] >= 'a' && str[i*2] <= 'f') c += (10 + str[i*2] - 'a') << 4;
		if (str[i*2] >= 'A' && str[i*2] <= 'F') c += (10 + str[i*2] - 'A') << 4;
		if (str[i*2+1] >= '0' && str[i*2+1] <= '9') c += (str[i*2+1] - '0');
		if (str[i*2+1] >= 'a' && str[i*2+1] <= 'f') c += (10 + str[i*2+1] - 'a');
		if (str[i*2+1] >= 'A' && str[i*2+1] <= 'F') c += (10 + str[i*2+1] - 'A');
		buf[i] = c;
	}
	return buf;
}

char *tohex(const uint8_t *bin, size_t l)
{
	static char buf[8192];
	static char digits[] = "0123456789abcdef";
	size_t i;
	for (i = 0; i < l; i++) 
	{
		buf[i*2  ] = digits[(bin[i] >> 4) & 0xF];
		buf[i*2+1] = digits[bin[i] & 0xF];
	}
	buf[l * 2] = 0;
	return buf;
}

#define PRINT_DUMP
#include "test-data.h"
int main( int argc, char *argv[] )
{
#if 0
	printf(">> Checking device connection status function.\n");
	hid_device_open();
	printf("0:Device available: %ld\n", hid_device_available());
	hid_device_close();
	printf("1:Device available: %ld\n", hid_device_available());
	hid_device_open();
	printf("Disconnect now...\n");
	Sleep(2000);
	printf("2:Device available: %ld\n", hid_device_available());
	return 0;
#endif

#if 1
	printf(">> Checking key_image function.\n");
	const char *ksecs[] =
	{
		"1b3182484ab35a657236f3ffb77734075d53e2f8b1f203220e681af35f17aa02",
		"66b6091156f0815783747eb21e5b32fed948beaa09ecd8775c27f86cad495c0e",
	};

	const char *kpubs[] =
	{
		"b89bdf893b11603e48cbb90174d9b173cb3988a1ba07248a366eeefb74f05600",
		"b45d27cc6eba1a1c8827f8d2f99a100e53d48710b088f575d26138aa381c3845",
	};

	const char *kims[] =
	{
		"4eb7780bd829aece45936721a47c060e6a48fcef2d6e201384826e284f9be1d6",
		"51b8db72220c2d6cf4ecaf4d919eafc84d3fbc12f94f8cbd1aac6f462346d716",
	};

	for(int i = 0; i < 2; i++)
	{
		xmr_seckey sec;
		xmr_pubkey pub;
		memcpy(sec.data, fromhex(ksecs[i]), 32);
		memcpy(pub.data, fromhex(kpubs[i]), 32);

		xmr_key_image ki;
		xmr_generate_key_image(&pub, &sec, &ki);

		xmr_key_image ex_ki;
		memcpy(ex_ki.data, fromhex(kims[i]), 32);
		if(memcmp(ki.data, ex_ki.data, 32) != 0)
		{
			printf("Failed: key generation functions don't match.\n");
			return -1L;
		}
	}

	printf("\t- all key_images generated match.\n");
#endif


#if 1
	printf(">> Checking key generation function.\n");
	xmr_seckey tspendkey;
	xmr_seckey tviewkey;
	xmr_pubkey tpub_spendkey;
	xmr_pubkey tpub_viewkey;

	memcpy(tspendkey.data, fromhex("c0b6063db394b014ccda4eaf830daed683acf042007e394681821807f9e58a01"), 32);
	memcpy(tviewkey.data, fromhex("100196b50f44d80c34d9c184abf6c8affd9b0a56b9b1c69b9ce42d8cdce078f4"), 32);

	printf("\t xmr_sec: %s\n", tohex(tspendkey.data, 32));
	printf("\t xmr_sec: %s\n", tohex(tviewkey.data, 32));

	xmr_generate_keys(&tpub_spendkey, &tspendkey, &tspendkey, true);
	xmr_generate_keys(&tpub_viewkey, &tviewkey, &tviewkey, true);

	printf("\t xmr_sec: %s\n", tohex(tspendkey.data, 32));
	printf("\t xmr_pub: %s\n", tohex(tpub_spendkey.data, 32));
	printf("\t xmr_sec: %s\n", tohex(tviewkey.data, 32));
	printf("\t xmr_pub: %s\n", tohex(tpub_viewkey.data, 32));

	crypto::secret_key ts;
	crypto::secret_key tv;
	crypto::public_key tpub_s;
	crypto::public_key tpub_v;

	memcpy(ts.data, fromhex("c0b6063db394b014ccda4eaf830daed683acf042007e394681821807f9e58a01"), 32);
	memcpy(tv.data, fromhex("100196b50f44d80c34d9c184abf6c8affd9b0a56b9b1c69b9ce42d8cdce078f4"), 32);

	printf("\t  cn_sec: %s\n", tohex((uint8_t *) ts.data, 32));
	printf("\t  cn_sec: %s\n", tohex((uint8_t *) tv.data, 32));

	crypto::generate_keys(tpub_s, ts, ts, true);
	crypto::generate_keys(tpub_v, tv, tv, true);

	printf("\t  cn_sec: %s\n", tohex((uint8_t *) ts.data, 32));
	printf("\t  cn_pub: %s\n", tohex((uint8_t *) tpub_s.data, 32));
	printf("\t  cn_sec: %s\n", tohex((uint8_t *) tv.data, 32));
	printf("\t  cn_pub: %s\n", tohex((uint8_t *) tpub_v.data, 32));

	if(memcmp(tspendkey.data, ts.data, 32) != 0 ||
			memcmp(tviewkey.data, tv.data, 32) != 0 ||
			memcmp(tpub_spendkey.data, tpub_s.data, 32) != 0 ||
			memcmp(tpub_viewkey.data, tpub_v.data, 32) != 0)
	{
		printf("Failed: key generation functions don't match.\n");
		return -1L;
	}

	printf("\t- all keys match.\n");
#endif

	if(argc < 5)
	{
		printf("Usage: test mix vin vout loops [account_index]\n");
		return -1L;
	}

	size_t tx_vin_count = atoi(argv[2]);
	size_t tx_vout_count = atoi(argv[3]);
	size_t tx_mixin_level = atoi(argv[1]);
	int account_index = 0;
	int sigloops = atoi(argv[4]);

	if(tx_mixin_level > 9)
		tx_mixin_level = 9;

	if(argc > 5)
		account_index = atoi(argv[5]);

	printf(">> Using account index: %d\n", account_index);
	//////////////////////////////////////////////////////////////////////////////
	printf(">> Testing signature function.\n");

	setup_random(42);
	for(int i = 0; i < _countof(rng_seg); i++)
	{
		uint8_t hash[32];
		generate_random_bytes(sizeof(hash), hash);
		if(memcmp(hash, fromhex(rng_seg[i]), sizeof(hash)) != 0)
		{
			printf("Failed: invalid random number generator sequence.\n");
			return -1L;
		}
	}

	// inputs
	xmr_hash sig_prefix_hash;
	xmr_key_image sig_keyimage;
	xmr_seckey sig_tx_eph_seckey;

	const size_t sig_secindex = 6;
	const size_t sig_npubs = _countof(s_pubs);

	xmr_pubkey sig_pubkeys[sig_npubs];

	memcpy(sig_prefix_hash.data, fromhex(s_prefix), sizeof(sig_prefix_hash.data));
	memcpy(sig_keyimage.data, fromhex(s_kimag), sizeof(sig_keyimage.data));
	memcpy(sig_tx_eph_seckey.data, fromhex(s_seckey), sizeof(sig_tx_eph_seckey.data));
	for(int i = 0; i < sig_npubs; i++)
	{
		memcpy(sig_pubkeys[i].data, fromhex(s_pubs[i]), sizeof(sig_pubkeys[i].data));
		// printf("pub%02d = %s\n", i, tohex(sig_pubkeys[i].data, sizeof(sig_pubkeys[i].data)));
	}

	if(true)
	{
		// outputs
		ec_scalar sum;
		xmr_signature signatures[sig_npubs];
		uint8_t stream[XMR_MAX_STREAM_LENGTH];
		setup_random(42);
		xmr_generate_ring_signature_stream(&sig_prefix_hash, &sig_keyimage, sig_pubkeys,
				sig_npubs, sig_secindex, stream, xmr_get_stream_size(sig_npubs), signatures, &sum);
		xmr_generate_ring_signature_cr(&sig_pubkeys[sig_secindex], &sig_tx_eph_seckey,
				&sum, stream, xmr_get_stream_size(sig_npubs), &signatures[sig_secindex]);

		for(int i = 0; i < sig_npubs; i++)
		{
			printf("\t |%02d = %s|\n", i, tohex(signatures[i].c.data, sizeof(signatures[i].c.data)));
			xmr_hash hash;
			memcpy(hash.data, fromhex(s_sig_c[i]), sizeof(hash.data));
			if(memcmp(hash.data, signatures[i].c.data, sizeof(hash.data)) != 0)
			{
				printf("Failed: ring signature data don't match @ index = %d.\n", i);
				return -1L;
			}
		}
		printf("\t- c signature data match.\n");

		for(int i = 0; i < sig_npubs; i++)
		{
			printf("\t |%02d = %s|\n", i, tohex(signatures[i].r.data, sizeof(signatures[i].r.data)));
			xmr_hash hash;
			memcpy(hash.data, fromhex(s_sig_r[i]), sizeof(hash.data));
			if(memcmp(hash.data, signatures[i].r.data, sizeof(hash.data)) != 0)
			{
				printf("Failed: ring signature data don't match @ index = %d.\n", i);
				return -1L;
			}
		}
		printf("\t- r signature data match.\n");
		printf("\t- all signatures match.\n");
	}

	//////////////////////////////////////////////////////////////////////////////
	Features *features = NULL; 
	features = NULL;
	wire_device device = {};
	if(wire_device_open(&device) != WIRE_SUCCESS)
	{
		printf("Error: trezor device handle could not be opened.\n");
		return -1L;
	}

	wire_initialize(&device, &features);

	if(device.dev == NULL || features == NULL)
	{
		printf("Error: trezor device not found.\n");
		return -1L;
	}
	printf(">> Trezor device located.\n");

	if (!features->initialized)
	{
#if 1
		printf(">> Device has not been initialized, resetting.\n");
		wire_reset_device(&device, "Kokko", false, false, false, 256);
#else
		printf("Error: device is not initialized.\n");
		return -1L;
#endif
	}

	printf("\t- tag: %s\n", features->vendor);
	printf(">> Supported coins: \n");
	for (size_t i = 0; i < features->n_coins; i++)
	{
		CoinType *coin = features->coins[i];
		printf("\t- %-10s (%s)\n", coin->coin_name, coin->coin_shortcut);
	}

	Address *address = NULL;
	wire_get_address(&device, &address, "44'/0'/0'/0/0", "Bitcoin", false);

	if (address != NULL)
	{
		printf("\t- BTC address: %s\n", address->address);
		free(address);
	}
	else
	{
		printf("Error: failed to get bitcoin address.\n");
		return -1L;
	}

	if(features)
		free(features);
	//////////////////////////////////////////////////////////////////////////////
	printf(">> Benchmarking ping.\n");
	TIME_MEASURE_START(time_ping);
	const int ping_iters = 1;
	for (int i = 0; i < ping_iters; i++)
		wire_ping(&device, "hello", false, false, false);
	TIME_MEASURE_FINISH(time_ping);
	printf("\t- ping time: %.3lf ms\n", time_ping / (double) ping_iters);

	//////////////////////////////////////////////////////////////////////////////
	uint8_t sessionkey[64];
	printf(">> Requesting session key.\n");
	if(wire_xmr_request_session_key(&device, sessionkey) != 0)
	{
		printf("Failed: session key request failed.\n");
		return -1L;
	}
	printf("\t- session key: %s\n", tohex(sessionkey, sizeof(sessionkey)));

	//////////////////////////////////////////////////////////////////////////////
	xmr_account account;
	memset(&account, 0, sizeof(account));
	printf(">> Requesting viewkey for index: %d\n", account_index);
	if(wire_xmr_request_viewkey(&device, false, NULL, account_index, sessionkey, account.sec_viewkey.data, account.pub_spendkey.data) != 0)
	{
		printf("Failed: viewkey request failed.\n");
		return -1L;
	}

	printf("\t- private viewkey : %s\n", tohex(account.sec_viewkey.data, sizeof(account.sec_viewkey.data)));
	printf("\t- public spendkey : %s\n", tohex(account.pub_spendkey.data, sizeof(account.pub_spendkey.data)));

    // FIXME: this wil lock-up now with >= v1.3.6 firmware, as the debug interface is
	// now always present regardless if debug link is enabled or not.
	DebugLinkState *state = NULL;
	if(wire_xmr_get_debug_link_state(&state) != 0)
	{
		printf("Failed: DEBUG_LINK not found. Enable in firmware.\n");
		return -1L;
	}

	memcpy(account.sec_spendkey.data, state->xmr_seckey.data, XMR_KEY_SIZE_BYTES);

	printf("\t- mnemonic: %s\n", state->mnemonic);

	free(state);
	state = NULL;

	printf("\t- private spendkey: %s\n", tohex(account.sec_spendkey.data, sizeof(account.sec_spendkey.data)));
	xmr_generate_keys(&account.pub_viewkey, &account.sec_viewkey, &account.sec_viewkey, true);

	xmr_address test_address;
	test_address.spendkey = account.pub_spendkey;
	test_address.viewkey = account.pub_viewkey;
	xmr_hash test_payment_id;

	char address_encoded[256];
	memset(address_encoded, 0, sizeof(address_encoded));
	xmr_get_b58_address(false, false, &test_address, &test_payment_id, address_encoded);
	printf("\t- Address: %s\n", address_encoded);

	// return 0;

	//////////////////////////////////////////////////////////////////////////////
	printf(">> Testing key_image generation.\n");
	// create a tx keypair
	xmr_pubkey tx_pubkey;
	xmr_seckey tx_seckey;
	xmr_generate_keys(&tx_pubkey, &tx_seckey, NULL, false);
	// get key derivation
	xmr_derivation derivation;
	xmr_generate_key_derivation(&tx_pubkey, &account.sec_viewkey, &derivation);

	// set the spendkey to fixed firmware spendkey (DEBUG_XMR enabled)
	// memcpy(account.sec_spendkey.data, fromhex(s_seckey), XMR_KEY_SIZE_BYTES);

	const int k_data_size = 256;
	xmr_key_image out_key_images[k_data_size];
	xmr_pubkey in_eph_pubkeys[k_data_size];
	uint64_t indices[k_data_size];

	// create dummy ephemeral pubkeys and indices
	for (int i = 0; i < k_data_size; i++)
	{
		xmr_pubkey tmp_eph_pubkey;
		xmr_derive_public_key(&derivation, i, &account.pub_spendkey, &tmp_eph_pubkey);
		memcpy(&in_eph_pubkeys[i], tmp_eph_pubkey.data, 32);
		indices[i] = i;
	}

	xmr_key_image expected_key_images[k_data_size];
	for (int i = 0; i < _countof(expected_key_images); i++)
	{
		xmr_seckey tmp_eph_seckey;
		xmr_derive_secret_key(&derivation, i, &account.sec_spendkey, &tmp_eph_seckey);
		xmr_generate_key_image(&in_eph_pubkeys[i], &tmp_eph_seckey, &expected_key_images[i]);
	}

	TIME_MEASURE_START(time_kimage);
	const int key_image_loops = 11;
	if(wire_xmr_generate_key_image(&device, derivation.data, (uint8_t *) in_eph_pubkeys, indices, key_image_loops,
			sessionkey, (uint8_t *) out_key_images) != 0)
	{
		printf("Failed: key_image generation failed.\n");
		return -1L;
	}
	TIME_MEASURE_FINISH(time_kimage);
	printf("\t- key image total: %.1lf ms / average: %.3lf ms\n", (double) time_kimage, time_kimage / (double) key_image_loops);
	for (int i = 0; i < key_image_loops; i++)
	{
		if (memcmp(out_key_images[i].data, expected_key_images[i].data, 32) != 0)
		{
			printf("gen: %s\n", tohex(out_key_images[i].data, 32));
			printf("exp: %s\n", tohex(expected_key_images[i].data, 32));
			printf("Failed: key_images don't match.\n");
			return -1L;
		}
	}
	srand(time(NULL));

	printf("\t- all key images match.\n");

	size_t tx_mix_count = tx_mixin_level + 1;
	const uint64_t tx_version = 1;
	const uint64_t tx_unlock_time = 1440388889;

	printf(">> Testing TX generation including signatures.\n");
	printf(">> VIN = %d, VOUT = %d, MIX = %d, LOOPS = %d\n", tx_vin_count, tx_vout_count, tx_mix_count, sigloops);

#if defined(SIGS_INTERNAL_K)
	printf(">> Using DEVICE random number generator for signature (slower/secure).\n");
#else
	printf(">> Using CLIENT random number generator for signature (fast/secure\?\?\?).\n");
#endif

	for (int loop = 0; loop < sigloops; loop++)
	{
		xmr_seckey tx_seckey1;
		xmr_pubkey tx_pubkey1;

		uint64_t tx_construction_id = 0;
		xmr_address dest_addresses[XMR_MAX_OUT_ADDRESSES];
		memset(dest_addresses, 0, sizeof(dest_addresses));
		// random addresses
		for (int i = 0; i < XMR_MAX_OUT_ADDRESSES; i++)
		{
			xmr_pubkey p0, p1;
			xmr_seckey s0, s1;
			xmr_generate_keys(&p1, &s1, NULL, false);
			xmr_generate_keys(&p0, &s0, NULL, false);

			memcpy(dest_addresses[i].spendkey.data, p0.data, 32);
			memcpy(dest_addresses[i].viewkey.data, p1.data, 32);
		}

		// returns tx seckey
		TIME_MEASURE_START(time_init);
		if(wire_xmr_generate_tx_init(&device, tx_version, tx_unlock_time, tx_mixin_level, tx_vin_count, tx_vout_count,
			(uint8_t *)dest_addresses, XMR_MAX_OUT_ADDRESSES, sessionkey, tx_seckey1.data, &tx_construction_id) != 0)
		{
			printf("Failed: wire_xmr_generate_tx_init.\n");
			return -1L;
		}

		if (tx_construction_id == 0)
		{
			printf("Failed: tx_construction_id is wrong.\n");
			return -1L;
		}
		TIME_MEASURE_FINISH(time_init);

		printf("\t- tx_init elapsed: %llu ms\n", time_init);

		// get tx pubkey from return tx seckey
		xmr_generate_keys(&tx_pubkey1, &tx_seckey1, &tx_seckey1, true);
		printf(">> Generating tx prefix_hash loop #%d\n", loop);
		printf("\t- tx seckey: %s\n", tohex(tx_seckey1.data, sizeof(tx_seckey1.data)));
		printf("\t- tx pubkey: %s\n", tohex(tx_pubkey1.data, sizeof(tx_pubkey1.data)));
		printf("\t- tx construction_id: %08llxh\n", tx_construction_id);

		uint64_t amounts[tx_vin_count > tx_vout_count ? tx_vin_count : tx_vout_count];
		xmr_derivation derivations[tx_vin_count];
		xmr_pubkey e_eph_pubkeys[tx_vin_count];
		xmr_seckey e_eph_seckeys[tx_vin_count];

		uint64_t out_indices[tx_vin_count];
		uint64_t vin_offsets[tx_vin_count * tx_mix_count];
		uint64_t actual_out_indices[tx_vin_count];
		xmr_pubkey actual_out_pubkeys[tx_vin_count * tx_mix_count];

		// fill data with something
		for (size_t i = 0; i < tx_vin_count; i++)
		{
			generate_random_bytes(8, &amounts[i]);
			// amounts[i] = (i + 1) * 1e12;
			out_indices[i] = i;
			actual_out_indices[i] = rand() % tx_mix_count;

			xmr_pubkey p;
			xmr_seckey s;
			// create a random real_out_tx_key to p
			xmr_generate_keys(&p, &s, NULL, false);

			xmr_derivation d;
			xmr_generate_key_derivation(&p, &account.sec_viewkey, &d);
			derivations[i] = d;

			xmr_pubkey eph_pubkey;
			xmr_derive_public_key(&d, out_indices[i], &account.pub_spendkey, &eph_pubkey);
			e_eph_pubkeys[i] = eph_pubkey;
#if defined(PRINT_DUMP1)
			printf("\t [%lu] %lu %lu %s\n", i, out_indices[i], actual_out_indices[i],
					tohex(e_eph_pubkeys[i].data, sizeof(e_eph_pubkeys[i].data)));
#endif

			uint16_t r;
			generate_random_bytes(2, &r);
			for (size_t j = 0; j < tx_mix_count; j++)
			{
				xmr_pubkey p;
				xmr_seckey s;
				int index = (i * tx_mix_count) + j;
				vin_offsets[index] = (i + 1) * (j + 1) * r;
				xmr_generate_keys(&p, &s, NULL, false);
				actual_out_pubkeys[index] = p;
#if defined(PRINT_DUMP1)
				printf("\t [%lu] %lu %s\n", index, vin_offsets[index], tohex(p.data, sizeof(p.data)));
#endif
			}
		}

		uint8_t encode_buf[65536];
		memset(encode_buf, 0, sizeof(encode_buf));
		uint8_t *p = encode_buf;
		size_t plen = 0;
		xmr_encode_varint(tx_version, &p, &plen);
		xmr_encode_varint(tx_unlock_time, &p, &plen);
		xmr_transaction _current_tx;
		memset(&_current_tx, 0, sizeof(_current_tx));
		Keccak_Init(&_current_tx.state, 256);

		xmr_encode_varint(tx_vin_count, &p, &plen);
		if(tx_vin_count == 0)
		{
			Keccak_Update(&_current_tx.state, encode_buf, plen << 3);
			p = encode_buf;
			plen = 0;
		}

		uint8_t expected_key_images[tx_vin_count * XMR_KEY_SIZE_BYTES];
		for (size_t i = 0; i < tx_vin_count; i++)
		{
			xmr_encode_varint(TXIN_TO_KEY_TAG, &p, &plen);
			xmr_encode_varint(amounts[i], &p, &plen);
			xmr_encode_varint(tx_mix_count, &p, &plen);
			for (size_t j = 0; j < tx_mix_count; j++)
			{
				xmr_encode_varint(vin_offsets[(i * tx_mix_count) + j], &p, &plen);
			}

			xmr_seckey eph_seckey;
			xmr_key_image ki;
			xmr_derive_secret_key(&derivations[i], out_indices[i], &account.sec_spendkey, &eph_seckey);
			xmr_generate_key_image(&e_eph_pubkeys[i], &eph_seckey, &ki);
			e_eph_seckeys[i] = eph_seckey;
#if defined(PRINT_DUMP1)
			printf("\t eph[%lu]: %s\n", i, tohex(e_eph_seckeys[i].data, sizeof(e_eph_seckeys[i].data)));
#endif
			memcpy(expected_key_images + i * XMR_KEY_SIZE_BYTES, ki.data, XMR_KEY_SIZE_BYTES);
	        memcpy(p, ki.data, sizeof(ki.data));
	        plen += sizeof(ki.data);

			Keccak_Update(&_current_tx.state, encode_buf, plen << 3);
			p = encode_buf;
			plen = 0;
		}

		TIME_MEASURE_START(time_vin);
		uint8_t generated_key_images[tx_vin_count * XMR_KEY_SIZE_BYTES];
		if(wire_xmr_generate_tx_vin(&device, amounts, (uint8_t *)derivations, (uint8_t *)e_eph_pubkeys,
				out_indices, tx_vin_count, vin_offsets, tx_mix_count, tx_construction_id, sessionkey, generated_key_images) != 0)
		{
			printf("Failed: wire_xmr_generate_tx_vin.\n");
			return -1L;
		}
		TIME_MEASURE_FINISH(time_vin);

		if(memcmp(generated_key_images, expected_key_images, sizeof(generated_key_images)) != 0)
		{
			printf("Failed: expected and generated key images don't match.\n");
			return -1L;
		}
		printf("\t- all key images match.\n");

		printf(">> VIN state:\n");
		for (int i = 0; i < 6; i++)
		{
			printf("\t |%s|\n", tohex(_current_tx.state.state + i * 8, 8));
		}
		printf("\t- tx_vin (%zu) elapsed: %llu ms\n", tx_vin_count, time_vin);

		int32_t vout_out_indices[tx_vout_count];
		for (size_t i = 0; i < tx_vout_count; i++)
		{
			amounts[i] = (uint64_t)((i + 0.95) * 1e12);
			vout_out_indices[i] = i == 0 ? -1 : i % XMR_MAX_OUT_ADDRESSES;
		}

		memset(encode_buf, 0, sizeof(encode_buf));
		p = encode_buf;
		plen = 0;
		xmr_encode_varint(tx_vout_count, &p, &plen);
		if(tx_vout_count == 0)
		{
			Keccak_Update(&_current_tx.state, encode_buf, plen << 3);
			p = encode_buf;
			plen = 0;
		}
		uint8_t expected_pubkeys[tx_vout_count * XMR_KEY_SIZE_BYTES];
		for (size_t i = 0; i < tx_vout_count; i++)
		{
			xmr_encode_varint(amounts[i], &p, &plen);
			xmr_encode_varint(TXOUT_TO_KEY_TAG, &p, &plen);

			xmr_pubkey *spend_pubkey = NULL;
			xmr_pubkey *view_pubkey = NULL;

			if (vout_out_indices[i] < 0)
			{
				spend_pubkey = &account.pub_spendkey;
				view_pubkey = &account.pub_viewkey;
			}
			else
			{
				size_t index = vout_out_indices[i];
				spend_pubkey = &dest_addresses[index].spendkey;
				view_pubkey = &dest_addresses[index].viewkey;
			}

			xmr_derivation derivation;
			xmr_generate_key_derivation(view_pubkey, &tx_seckey1, &derivation);

			xmr_pubkey eph_pubkey;
			xmr_derive_public_key(&derivation, i, spend_pubkey, &eph_pubkey);
			memcpy(expected_pubkeys + i * XMR_KEY_SIZE_BYTES, eph_pubkey.data, XMR_KEY_SIZE_BYTES);

	        memcpy(p, eph_pubkey.data, sizeof(eph_pubkey.data));
	        plen += sizeof(eph_pubkey.data);

			Keccak_Update(&_current_tx.state, encode_buf, plen << 3);
			p = encode_buf;
			plen = 0;
		}

		TIME_MEASURE_START(time_vout);
		uint8_t generated_pubkeys[tx_vout_count * XMR_KEY_SIZE_BYTES];
		if(wire_xmr_generate_tx_vout(&device, amounts, vout_out_indices, tx_vout_count, tx_construction_id, sessionkey, generated_pubkeys) != 0)
		{
			printf("Failed: wire_xmr_generate_tx_vout.\n");
			return -1L;
		}
		TIME_MEASURE_FINISH(time_vout);

		if(memcmp(generated_pubkeys, expected_pubkeys, sizeof(generated_pubkeys)) != 0)
		{
			printf("Failed: expected and generated eph pubkeys don't match.\n");
			return -1L;
		}
		printf("\t- all pubkeys match.\n");

		printf(">> VOUT state:\n");
		for (int i = 0; i < 6; i++)
		{
			printf("\t |%s|\n", tohex(_current_tx.state.state + i * 8, 8));
		}
		printf("\t- tx_vout (%zu) elapsed: %llu ms\n", tx_vout_count, time_vout);

		uint8_t payment_id[32];
		generate_random_bytes(sizeof(payment_id), payment_id);
		memset(encode_buf, 0, sizeof(encode_buf));

		size_t count = 0;

		// use a 32 byte length payment_id
		xmr_add_payment_id_to_extra(payment_id, sizeof(payment_id), &dest_addresses[0].viewkey, &tx_seckey1, encode_buf, &count);
		printf("count: %d\n", count);
		xmr_add_tx_pubkey_to_extra(&tx_pubkey1, encode_buf, &count);
		printf("count: %d\n", count);

		plen = 0;
		uint8_t final_buffer[256];
		p = final_buffer;
		xmr_encode_varint(count, &p, &plen);
		memcpy(p, encode_buf, count);
		plen += count;

		xmr_hash tx_computed_prefix_hash;
		Keccak_Update(&_current_tx.state, final_buffer, plen << 3);
		Keccak_Final(&_current_tx.state, tx_computed_prefix_hash.data);

		printf("\t- tx_extra calcu: %s\n", tohex(encode_buf, count));

		xmr_hash tx_generated_prefix_hash;
		uint8_t extra_bytes[68];
		size_t extra_bytes_length = 0;
		TIME_MEASURE_START(time_extra);
		//hid_device_close();
#if 1
		if(wire_xmr_generate_tx_extra(&device, payment_id, sizeof(payment_id), tx_generated_prefix_hash.data, extra_bytes,
			&extra_bytes_length, tx_construction_id, sessionkey) != 0)
		{
			printf("Failed: wire_xmr_generate_tx_extra.\n");
			return -1L;
		}
#else
		memcpy(tx_generated_prefix_hash.data, tx_computed_prefix_hash.data, 32);
#endif
		TIME_MEASURE_FINISH(time_extra);
		printf("\t- extra_bytes_length: %d\n", extra_bytes_length);
		printf("\t- tx_extra bytes: %s\n", tohex(extra_bytes, extra_bytes_length));

		if(extra_bytes_length != count || memcmp(extra_bytes, encode_buf, extra_bytes_length) != 0)
		{
			printf("Failed: extra bytes don't match.\n");
			return -1L;
		}
		printf("\t- tx_extra elapsed: %llu ms\n", time_extra);

		printf("\t- expected tx_prefix : %s\n", tohex(tx_computed_prefix_hash.data, sizeof(tx_computed_prefix_hash.data)));
		printf("\t- generated tx_prefix: %s\n", tohex(tx_generated_prefix_hash.data, sizeof(tx_generated_prefix_hash.data)));

		if(memcmp(tx_computed_prefix_hash.data, tx_generated_prefix_hash.data, sizeof(tx_computed_prefix_hash.data)) != 0)
		{
			printf("Failed: generated and expected tx prefix_hash don't match.\n");
			return -1L;
		}
		printf("\t- actual and generated tx prefix match..\n");

		ec_scalar sum;
		xmr_signature expected_signatures[tx_vin_count * tx_mix_count];
		xmr_signature generated_signatures[tx_vin_count * tx_mix_count];
		memset(expected_signatures, 0, sizeof(expected_signatures));
		memset(generated_signatures, 0, sizeof(generated_signatures));


		printf(">> Creating signatures:\n");
		for(int i = 0; i < tx_vin_count; i++)
		{
			uint8_t stream[XMR_MAX_STREAM_LENGTH];
			setup_random(i);
			const xmr_key_image *key_images = (xmr_key_image *) generated_key_images;
			const xmr_pubkey *pubkeys = (xmr_pubkey *) &actual_out_pubkeys[i * tx_mix_count];
			xmr_signature *sigs = (xmr_signature *) &expected_signatures[i * tx_mix_count];

			int out_index = actual_out_indices[i];
			xmr_generate_ring_signature_stream(&tx_computed_prefix_hash, &key_images[i], pubkeys,
					tx_mix_count, out_index, stream, xmr_get_stream_size(tx_mix_count), sigs, &sum);
			xmr_generate_ring_signature_cr(&pubkeys[out_index], &e_eph_seckeys[i],
					&sum, stream, xmr_get_stream_size(tx_mix_count), &sigs[out_index]);
		}

		TIME_MEASURE_START(time_sigs);
		size_t length_per_stream = xmr_get_stream_size(tx_mix_count);
		uint8_t a_streams[tx_vin_count * length_per_stream];
		ec_scalar a_sums[tx_vin_count];
		xmr_pubkey a_pubkeys[tx_vin_count];
		uint64_t a_indices[tx_vin_count];
		xmr_signature a_sigs[tx_vin_count];
		ec_scalar a_ks[tx_vin_count];

		memset(a_sigs, 0, sizeof(a_sigs));

		for(int i = 0; i < tx_vin_count; i++)
		{
			setup_random(i);
			const xmr_key_image *key_images = (xmr_key_image *) generated_key_images;
			const xmr_pubkey *pubkeys = (xmr_pubkey *) &actual_out_pubkeys[i * tx_mix_count];
			xmr_signature *sigs = (xmr_signature *) &generated_signatures[i * tx_mix_count];

			int out_index = actual_out_indices[i];
#if defined(SIGS_INTERNAL_K)
			xmr_generate_ring_signature_stream(&tx_computed_prefix_hash, &key_images[i], pubkeys,
						tx_mix_count, out_index, a_streams + (i * length_per_stream), length_per_stream, sigs, &a_sums[i]);
#else
			// xmr_generate_ring_signature_stream2(&sig_prefix_hash, &sig_keyimage, sig_pubkeys, sig_npubs, sig_secindex, &k, signatures);
			xmr_generate_ring_signature_stream2(&tx_computed_prefix_hash, &key_images[i], pubkeys, tx_mix_count, out_index, &a_ks[i], sigs);
#endif
			a_pubkeys[i] = pubkeys[out_index];
			a_indices[i] = actual_out_indices[i];
			a_sigs[i] = sigs[out_index];
			// printf("cc[%d]: %s\n", out_index, tohex(sigs[out_index].c.data, 32));
		}

		ec_scalar scalars[tx_vin_count];
		memset(scalars, 0, sizeof(scalars));
		for (size_t i = 0; i < tx_vin_count; i++)
		{
			xmr_derivation_to_scalar(&((const xmr_derivation *) derivations)[i], out_indices[i], &scalars[i]);
			xmr_seckey ephseckey;
			xmr_derive_secret_key2(&scalars[i], &account.sec_spendkey, &ephseckey);
			if(memcmp(ephseckey.data, e_eph_seckeys[i].data, sizeof(ephseckey.data)) != 0)
			{
				printf("Failed: ephemeral secret keys don't match.\n");
				return -1L;
			}
		}

		if(wire_xmr_generate_tx_signature(&device, a_streams, length_per_stream, (uint8_t *) derivations, (uint8_t *) a_sums, out_indices,
				(uint8_t *) a_pubkeys, tx_vin_count, tx_construction_id, sessionkey, (uint8_t *) a_sigs) != 0)
		{
			printf("Failed: wire_xmr_generate_signature.\n");
			return -1L;
		}

		TIME_MEASURE_FINISH(time_sigs);
		printf("\t- tx_sigs (%zu x %zu) elapsed: %llu ms\n", tx_vin_count, tx_mix_count, time_sigs);

		for(int i = 0; i < tx_vin_count; i++)
		{
			const xmr_signature *esigs = &expected_signatures[i * tx_mix_count];
			xmr_signature *gsigs = &generated_signatures[i * tx_mix_count];
			int index = a_indices[i];
			gsigs[index] = a_sigs[i];

#if defined(PRINT_DUMP)
			bool failed_c = memcmp(esigs[index].c.data, gsigs[index].c.data, sizeof(esigs[index].c.data)) != 0;
			bool failed_r = memcmp(esigs[index].r.data, gsigs[index].r.data, sizeof(esigs[index].r.data)) != 0;

			if(failed_c || failed_r)
			{
				std::string ec = tohex(esigs[index].c.data, sizeof(esigs[index].c.data));
				std::string er = tohex(esigs[index].r.data, sizeof(esigs[index].r.data));
				std::string gc = tohex(gsigs[index].c.data, sizeof(gsigs[index].c.data));
				std::string gr = tohex(gsigs[index].r.data, sizeof(gsigs[index].r.data));
				printf("\t |e:%04d:%04d = %s %s|\n", i, index, ec.c_str(), er.c_str());
				printf("\t |g:%04d:%04d = %s %s|", i, index, gc.c_str(), gr.c_str());
				printf(" <- failed\n");
			}
#endif
		}

		for(int i = 0; i < tx_vin_count; i++)
		{
			const xmr_signature *esigs = &expected_signatures[i * tx_mix_count];
			const xmr_signature *gsigs = &generated_signatures[i * tx_mix_count];

			int out_index = a_indices[i];
			for(int j = 0; j < tx_mix_count; j++)
			{
				bool failed_c = memcmp(esigs[j].c.data, gsigs[j].c.data, sizeof(esigs[j].c.data)) != 0;
				bool failed_r = memcmp(esigs[j].r.data, gsigs[j].r.data, sizeof(esigs[j].r.data)) != 0;

				if(failed_c || failed_r)
				{
					printf("Failed: signature c/r values don't match at vin = %d, index = %d.\n", i, j);
					return -1L;
				}
			}
		}

		printf("\t- all signatures match");
		printf("\t- tx processing total elapsed: %llu ms\n", time_init + time_vin + time_vout + time_sigs + time_extra);
		printf("\n");
 	}
	printf("Done.");

	return 0;
}
