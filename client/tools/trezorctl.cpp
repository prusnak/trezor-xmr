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
#include <iostream>
#include <fstream>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "crypto/crypto.h"

#include "include_base_utils.h"
#include "misc_language.h"
#include "profile_tools.h"
#include "file_io_utils.h"

#include "crypto-ops.h"
#include "crypto-xmr.h"
#include "hash-ops.h"
#include "trezor-xmr/shared/stream.h"
#include "kokko.h"
#include "profile_tools.h"

#include "protobuf-c/types.pb-c.h"
#include "protobuf-c/protobuf-c.h"
#include "protobuf-c/messages.pb-c.h"
#include "protobuf-c/storage.pb-c.h"

#include "stream.h"
#include "terminal.h"

#include "mnemonics/electrum-words.h"
#ifdef __cplusplus
extern "C" {
#endif
#include "bip39.h"
#include "bip32.h"
#include "aes.h"
#include "pbkdf2.h"
#include "keccak.h"
#include "sha2.h"
#include "curves.h"
void setup_random(int c);
void generate_random_bytes(size_t n, void *result);

#ifdef __cplusplus
}
#endif

#if !defined(_countof)
#define _countof(_a) (sizeof(_a) / sizeof(_a[0]))
#endif

////////////////////////////////////////////////////////////////////////////////
const char *device_operations[] =
{
	"wipe",
	"reset",
	"recover",
	"recover_mnemonic",
	"update"
};

const char *usage[] =
{
	"",
	"label pin_protect pass_protect display_random strength",
	"label pin_protect pass_protect verify_words word_count",
	"index passphrase language word_list",
	"firmware_file"
};

enum device_operation_t
{
	WIPE = 0, RESET, RECOVER, RECOVER_MNEMONIC, FIRMWARE_UPDATE, NONE = -1
};

static char *_word_list[24];
static size_t _word_count = 0;
static bool _using_indexed_word_list = false;

////////////////////////////////////////////////////////////////////////////////
bool wipe_device(void)
{
	wire_device device = {};
	if(wire_device_open(&device) != WIRE_SUCCESS)
	{
		printf("Error: open device failed.\n");
		return false;
	}

	bool res = wire_wipe_device(&device) == WIRE_SUCCESS;
	wire_device_close(&device);
	return res;
}

////////////////////////////////////////////////////////////////////////////////
bool reset_device(int argc, char *argv[])
{
	if(argc < 6)
	{
		printf("USAGE: trezorctl %s %s\n", device_operations[device_operation_t::RESET], usage[device_operation_t::RESET]);
		return false;
	}

	size_t index = 2;
	const char *label = argv[index++];
	bool pin_protect = atoi(argv[index++]) > 0;
	bool pass_protect = atoi(argv[index++]) > 0;
	bool display_random = atoi(argv[index++]) > 0;
	uint32_t strength = atoi(argv[index++]);

	if (strength != 128 && strength != 192 && strength != 256)
	{
		printf("Error: supported strength values are 128, 192 and 256.\n");
		return false;
	}

	wire_device device = {};
	if(wire_device_open(&device) != WIRE_SUCCESS)
	{
		printf("Error: open device failed.\n");
		return false;
	}
	bool res = wire_reset_device(&device, label, pin_protect, pass_protect, display_random, strength) == WIRE_SUCCESS;
	wire_device_close(&device);
	return res;
}

////////////////////////////////////////////////////////////////////////////////
static int recovery_function(char *word, size_t length)
{
	// get words
	if(!_using_indexed_word_list)
	{
		printf("Enter word required: ");
		ssize_t read = read_console(false, word, length);
	}
	// get indices
	else
	{
		char buffer[128];
		printf("Enter index required: ");
		ssize_t read = read_console(false, buffer, sizeof(buffer));
		int index = atoi(buffer) - 1;
		if(index > (int) _word_count || index < 0)
		{
			return WIRE_ERROR;
		}

		strncpy(word, _word_list[index], length);
		word[length - 1] = '\0';
	}

	return WIRE_SUCCESS;
}

bool recover_device(int argc, char *argv[])
{
	if(argc < 7)
	{
		printf("USAGE: trezorctl %s %s\n", device_operations[device_operation_t::RECOVER], usage[device_operation_t::RECOVER]);
		return false;
	}

	size_t index = 2;
	const char *label = argv[index++];
	bool pin_protect = atoi(argv[index++]) > 0;
	bool pass_protect = atoi(argv[index++]) > 0;
	bool verify = atoi(argv[index++]) > 0;
	size_t word_count = 0;
	if(argc == 30 || argc == 24 || argc == 18)
	{
		for(int i = index; i < argc; i++)
		{
			_word_list[i - index] = argv[i];
		}

		_word_count = argc - index;
		_using_indexed_word_list = true;
	}
	else
	{
		word_count = atoi(argv[index++]);
		if(word_count != 12 && word_count != 18 && word_count != 24)
		{
			printf("Error: word_count must be 12, 18 or 24\n");
			return false;
		}

		_word_count = word_count;
		_using_indexed_word_list = false;
	}

	wire_set_recovery_word_function(recovery_function);

	wire_device device = {};
	if(wire_device_open(&device) != WIRE_SUCCESS)
	{
		printf("Error: open device failed.\n");
		return false;
	}
	bool res = wire_recover_device(&device, label, _word_count, pin_protect, pass_protect, verify) == WIRE_SUCCESS;
	wire_device_close(&device);
	return res;
}

////////////////////////////////////////////////////////////////////////////////
static void print_supported_languages(std::vector<std::string> &languages)
{
	printf("\tSupported languages:\n");
	for(const auto &language : languages)
	{
		printf("\t\t%s\n", language.c_str());
	}
}

bool recover_mnemonic(int argc, char *argv[])
{
	std::vector<std::string> languages;
	crypto::ElectrumWords::get_language_list(languages);

	if(argc != 17 && argc != 23 && argc != 29)
	{
		printf("USAGE: trezorctl %s %s\n", device_operations[device_operation_t::RECOVER_MNEMONIC],
				usage[device_operation_t::RECOVER_MNEMONIC]);
		print_supported_languages(languages);
		return false;
	}
	size_t index = 2;
	uint32_t account_index = atoi(argv[index++]);
	const char *passphrase = argv[index++];
	bool has_passphrase = strlen(passphrase) != 0;
	std::string language = argv[index++];

	if (std::find(languages.begin(), languages.end(), language) == languages.end())
	{
		printf("Error: invalid language name specified.\n");
		print_supported_languages(languages);
		return false;
	}

	char mnemonic[241];
	_word_count = argc - index;
	strncpy(mnemonic, argv[index++], sizeof(mnemonic));
	mnemonic[sizeof(mnemonic)  - 1] = '\0';
	for(int i = index; i < argc; i++)
	{
		_word_list[i - index] = argv[i];
		strncat(mnemonic, " ", sizeof(mnemonic) - strlen(mnemonic) - 1);
		strncat(mnemonic, argv[i], sizeof(mnemonic) - strlen(mnemonic) - 1);
	}

	// recover seed and get root node
	uint8_t seed[64];
	HDNode node;
	memset(seed, 0, sizeof(seed));
	mnemonic_to_seed(mnemonic, passphrase, seed, nullptr);
	hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &node);

	uint32_t address_n[6];
	size_t address_n_count = sizeof(address_n) / sizeof(address_n[0]);

	// FIXME: this gets a derivation path for the node of 6 elements.
	// Can be modified for a more "useful" path if needed.
	address_n[0] = 0x80786D72;
	for(size_t i = 1; i < address_n_count - 1; i++)
		address_n[i] = 0x80000000 + i;

	// set index for derivation path
	address_n[5] = account_index | 0x80000000;


	// get derived node
	if(hdnode_private_ckd_cached(&node, address_n, address_n_count) == 0)
	{
		printf("Error: unable to get derived node.\n");
		return false;
	}

	xmr_seckey spendkey;
	xmr_seckey viewkey;
	// get keys
	xmr_generate_keys_from_seed(node.private_key, sizeof(node.private_key),
			nullptr, &viewkey, &spendkey, nullptr);

	xmr_address address;
	xmr_generate_keys(&address.spendkey, &spendkey, &spendkey, true);
	xmr_generate_keys(&address.viewkey, &viewkey, &viewkey, true);

	char encoded[256];
	xmr_get_b58_address(false, false, &address, nullptr, encoded);
	printf("Spend key: %s\n", epee::string_tools::pod_to_hex(spendkey).c_str());
	printf(" View key: %s\n", epee::string_tools::pod_to_hex(viewkey).c_str());

	printf("Wallet address: %s\n", encoded);

	crypto::secret_key seckey;
	memcpy(seckey.data, spendkey.data, sizeof(seckey.data));

	std::string mnemonic_words;
	crypto::ElectrumWords::bytes_to_words(seckey, mnemonic_words, language);

	printf("Mnemonic: %s\n", mnemonic_words.c_str());
	return true;
}

////////////////////////////////////////////////////////////////////////////////
bool update_firmware(int argc, char *argv[])
{
	if(argc < 3)
	{
		printf("USAGE: trezorctl %s %s\n", device_operations[device_operation_t::FIRMWARE_UPDATE], usage[device_operation_t::FIRMWARE_UPDATE]);
		return false;
	}

	try
	{
		char *filename = argv[2];
		std::ifstream file(filename, std::ios::in | std::ios::binary);
		if(!file.is_open())
		{
			printf("Error: unable to open firmware file '%s'.\n", filename);
			return false;
		}

		file.seekg(0, std::ios::end);
		size_t filesize = file.tellg();
		if(filesize == 0)
		{
			printf("Error: firmware file is empty.\n");
			return false;
		}

		file.seekg(0, std::ios::beg);
		std::vector<uint8_t> buffer;
		buffer.resize(filesize);
		file.read((char *) buffer.data(), filesize);
		file.close();

		if(memcmp(buffer.data(), "TRZR", 4) != 0)
		{
			printf("Error: invalid firmware file.\n");
			return false;
		}

		xmr_hash hash;
		SHA256_CTX context;

		sha256_Init(&context);
		sha256_Update(&context, buffer.data() + 256, buffer.size() - 256);
		sha256_Final(&context, hash.data);
		buffer.clear();

		printf("Firmware hash: %s\n", epee::string_tools::pod_to_hex(hash).c_str());
		printf("Firmware size: %zu\n", filesize);

		Features *features = nullptr;
		wire_device device = {};
		if(wire_device_open(&device) != WIRE_SUCCESS)
		{
			printf("Error: open device failed.\n");
			return false;
		}

		if(wire_initialize(&device, &features) != WIRE_SUCCESS)
		{
			printf("Error: initialize failed.\n");
			return false;
		}

		if(!features->bootloader_mode)
		{
			free(features);
			printf("Error: trezor not in bootloader mode.\n");
			return false;
		}

		if(features)
			free(features);
		features = nullptr;

		return wire_firmware_update(&device, filename) == WIRE_SUCCESS;
	}
	catch(const std::exception &e)
	{
		printf("Error: exception encountered '%s'\n", e.what());
		return false;
	}

	return true;
}

////////////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[])
{
	if(argc < 2)
	{
		printf("USAGE: trezorctl operation [params]\n");
		printf("SUPPORTED operations:\n");
		for(size_t i = 0; i < _countof(device_operations); i++)
			printf("\t%s\n", device_operations[i]);

		return -1L;
	}

	std::string operation = argv[1];
	device_operation_t op = device_operation_t::NONE;
	for(size_t i = 0; i < _countof(device_operations); i++)
	{
		if(operation == device_operations[i])
		{
			op = (device_operation_t) i;
		}
	}

	bool res = true;
	switch(op)
	{
	default:
		printf("Error: no valid operation found.\n");
		return -1L;
	case device_operation_t::WIPE:
		res = wipe_device();
		break;
	case device_operation_t::RESET:
		res = reset_device(argc, argv);
		break;
	case device_operation_t::RECOVER:
		res = recover_device(argc, argv);
		break;
	case device_operation_t::RECOVER_MNEMONIC:
		res = recover_mnemonic(argc, argv);
		break;
	case device_operation_t::FIRMWARE_UPDATE:
		res = update_firmware(argc, argv);
		break;
	}

	return res ? 0L : -1L;
}
