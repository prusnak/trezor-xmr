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

#include "trezor.h"
#include "kokko.h"

#include "crypto-xmr.h"
#include "trezor-xmr/shared/stream.h"
#include <string.h>
#include "profile_tools.h"
#include "log.h"

#include "cryptonote_core/account.h"
#include "cryptonote_core/cryptonote_format_utils.h"
#include "syncobj.h"

namespace kokko
{

//-------------------------------------------------------------------------------------------------
trezor::trezor() :
		m_session_initialized(false),
		m_features(nullptr),
		m_account_index(0),
		m_account_initialized(false),
		m_default_passphrase_function(nullptr)
{
	memset(m_session_key, 0, sizeof(m_session_key));
	m_device.dev = nullptr;
	m_device.ver = HID_V1;

	// store the original password prompt function
	m_default_passphrase_function = wire_set_passphrase_function(trezor::passphrase_function);
}

//-------------------------------------------------------------------------------------------------
trezor::~trezor()
{
	shutdown();
}

//-------------------------------------------------------------------------------------------------
bool trezor::get_session_key(bool renew)
{
	if(renew)
	{
		m_session_initialized = wire_xmr_request_session_key(&m_device, m_session_key) == WIRE_SUCCESS;
	}

	return m_session_initialized;
}

//-------------------------------------------------------------------------------------------------
bool trezor::initialize()
{
	CRITICAL_REGION_LOCAL(m_device_lock);

	if(m_features != nullptr)
		return true;

	if(wire_device_open(&m_device) != WIRE_SUCCESS)
		return false;

	// one-time params
	Features *features = nullptr;
	if(wire_initialize(&m_device, &features) != WIRE_SUCCESS)
		return false;

	if (!features->initialized)
	{
		free(features);
		return false;
	}

	bool xmr_found = false;
	for (size_t i = 0; i < features->n_coins; i++)
	{
		CoinType *coin = features->coins[i];
		if(strcmp(coin->coin_shortcut, "XMR") == 0)
		{
			xmr_found = true;
			break;
		}
	}

	if(!xmr_found)
		return false;

	m_features = features;

	return true;
}

//-------------------------------------------------------------------------------------------------
void trezor::shutdown()
{
	CRITICAL_REGION_LOCAL(m_device_lock);

	if(m_features != nullptr)
	{
		free(m_features);
		m_features = nullptr;
	}

	m_account = {};
	m_account_initialized = false;
	wire_device_close(&m_device);
}

//-------------------------------------------------------------------------------------------------
Features *trezor::get_features()
{
	CRITICAL_REGION_LOCAL(m_device_lock);

	if(!initialize())
		return nullptr;

	return m_features;
}

//-------------------------------------------------------------------------------------------------
bool trezor::has_password_protection()
{
	if(get_features() == nullptr)
		return false;

	return (m_features->has_passphrase_protection && m_features->passphrase_protection);
}

//-------------------------------------------------------------------------------------------------
bool trezor::get_account(bool display, cryptonote::account_keys &account, uint32_t index, const std::string &password)
{
	CRITICAL_REGION_LOCAL(m_device_lock);

	if(!m_account_initialized || (m_account_initialized && m_account_index != index))
	{
		m_account = {};
		m_account_initialized = false;
		trezor::m_password.clear();

		if(has_password_protection())
		{
			if(password.empty())
			{
				wire_set_passphrase_function(m_default_passphrase_function);
			}
			else
			{
				trezor::m_password = password;
				wire_set_passphrase_function(trezor::passphrase_function);
			}
		}

		if(!initialize())
			return false;

		if(!get_session_key(true))
			return false;

		if(wire_xmr_request_viewkey(&m_device, display, nullptr, index, m_session_key, m_account.sec_viewkey.data,
				m_account.pub_spendkey.data) != WIRE_SUCCESS)
		{
			trezor::m_password.clear();
			m_account = {};
			TLOG("Failed: wire_xmr_request_viewkey.\n");
			return false;
		}

		trezor::m_password.clear();
		xmr_public_key(&m_account.sec_viewkey, &m_account.pub_viewkey);
	}

	copy_address_to_account_keys(account);

	m_account_initialized = true;
	m_account_index = index;
	return true;
}

//-------------------------------------------------------------------------------------------------
bool trezor::get_key_images(std::vector<crypto::key_image> &key_images, std::vector<cryptonote::keypair> &ephpairs,
		const crypto::public_key &tx_pubkey, const std::vector<size_t> &outs)
{
	CRITICAL_REGION_LOCAL(m_device_lock);

	if(!m_account_initialized)
		return false;

	if(!is_connected())
	{
		if(!reconnect())
			return false;
	}

	if(!get_session_key(false))
		return false;

	std::vector<uint64_t> indices;
	ephpairs.clear();
	key_images.clear();
	key_images.resize(outs.size());

	std::vector<xmr_pubkey> ephpubkeys;

	xmr_derivation derivation;
	xmr_generate_key_derivation((xmr_pubkey *) &tx_pubkey, &m_account.sec_viewkey, &derivation);

	for(const auto output_index : outs)
	{
		cryptonote::keypair keys;
		xmr_derive_public_key(&derivation, output_index, &m_account.pub_spendkey, (xmr_pubkey *) &keys.pub);
		ephpairs.push_back(keys);
		ephpubkeys.push_back(*((xmr_pubkey *) &keys.pub));
		indices.push_back(output_index);
	}

	TIME_MEASURE_START(time_key_image);
	if(wire_xmr_generate_key_image(&m_device, derivation.data, (uint8_t *) ephpubkeys.data(), indices.data(), outs.size(),
			m_session_key, (uint8_t *) key_images.data()) != 0)
	{
		TLOG("Failed: wire_xmr_generate_key_image.\n");
		return false;
	}
	TIME_MEASURE_FINISH(time_key_image);
	return true;
}

//-------------------------------------------------------------------------------------------------
bool trezor::display_address()
{
	CRITICAL_REGION_LOCAL(m_device_lock);

	if(!m_account_initialized)
		return false;

	if(!is_connected())
	{
		if(!reconnect())
			return false;
	}

	if(!get_session_key(false))
		return false;

	xmr_seckey seckey;
	xmr_pubkey pubkey;
	if(wire_xmr_request_viewkey(&m_device, true, nullptr, m_account_index, m_session_key, seckey.data,
			pubkey.data) != WIRE_SUCCESS)
	{
		TLOG("Failed: display_address.\n");
		return false;
	}

	return true;
}

//-------------------------------------------------------------------------------------------------
bool trezor::generate_tx(cryptonote::transaction &tx, const std::vector<cryptonote::tx_source_entry> &sources, const std::vector<cryptonote::tx_destination_entry> &shuffled_dests,
		uint64_t unlock_time, uint64_t version, trezor::payment_id_type pid_type, const crypto::hash &pid)
{
	CRITICAL_REGION_LOCAL(m_device_lock);

	if(!m_account_initialized)
		return false;

	if(!is_connected())
	{
		if(!reconnect())
			return false;
	}

	if(!get_session_key(false))
		return false;

	if(sources.size() == 0)
		return false;

	tx.vin.clear();
	tx.vout.clear();
	tx.signatures.clear();
	tx.version = version;
	tx.unlock_time = unlock_time;

	size_t vin_count = sources.size();
	size_t vout_count = shuffled_dests.size();
	size_t mixin_count = sources[0].outputs.size();
	size_t mixin_level = mixin_count - 1;

	if(mixin_count > XMR_MAX_MIXIN_COUNT)
	{
		TLOG("Failed: Mixin level too high, max is %d.\n", XMR_MAX_MIXIN_COUNT - 1);
		return false;
	}
	// build destination addresses
	std::vector<xmr_address> vout_addrs;
	std::vector<int32_t> vout_indices;
	std::vector<uint64_t> vout_amounts;

	int index = 0;
	for(const auto &dest : shuffled_dests)
	{
		vout_amounts.push_back(dest.amount);
		if(memcmp(m_account.pub_viewkey.data, dest.addr.m_view_public_key.data, sizeof(m_account.pub_viewkey.data)) != 0 ||
				memcmp(m_account.pub_spendkey.data, dest.addr.m_spend_public_key.data, sizeof(m_account.pub_spendkey.data)) != 0)
		{
			xmr_address addr;
			memcpy(addr.viewkey.data, dest.addr.m_view_public_key.data, sizeof(addr.viewkey.data));
			memcpy(addr.spendkey.data, dest.addr.m_spend_public_key.data, sizeof(addr.spendkey.data));

			switch(pid_type)
			{
			default:
			case payment_id_type::normal:
			case payment_id_type::none:
				addr.addr_type = XMR_ADDR_DEFAULT;
				break;
			case payment_id_type::encrypted:
				addr.addr_type = XMR_ADDR_INTEGRATED_V1;
				break;
			}

			int found_index = -1;
			for(size_t i = 0; i < vout_addrs.size(); i++)
			{
				if(memcmp(&addr, &vout_addrs[i], sizeof(addr)) == 0)
				{
					found_index = i;
					break;
				}
			}

			if(found_index >= 0)
			{
				vout_indices.push_back(found_index);
			}
			else
			{
				vout_indices.push_back(index);
				vout_addrs.push_back(addr);
				++index;
			}
		}
		else
		{
			vout_indices.push_back(-1);
		}
	}

	if(vout_addrs.size() > XMR_MAX_OUT_ADDRESSES)
	{
		TLOG("Failed: Too many destination addresses, max is %d.\n", XMR_MAX_OUT_ADDRESSES);
		return false;
	}
	uint64_t construction_id;
	//xmr_seckey tx_seckey;
	if(wire_xmr_generate_tx_init(&m_device, version, unlock_time, mixin_level, vin_count, vout_count, (uint8_t *) vout_addrs.data(),
			vout_addrs.size(), m_session_key, NULL, &construction_id) != WIRE_SUCCESS)
	{
		TLOG("Failed: wire_xmr_generate_tx_initn.\n");
		return false;
	}

	std::vector<uint64_t> vin_amounts;
	std::vector<uint64_t> vin_out_indices;
	std::vector<uint64_t> vin_offsets;
	std::vector<xmr_derivation> derivations;
	std::vector<xmr_pubkey> vin_eph_pubkeys;
	std::vector<xmr_pubkey> sig_pubkeys;
	std::vector<uint64_t> sig_indices;

	for(size_t i = 0; i < sources.size(); i++)
	{
		auto &src = sources[i];
		vin_amounts.push_back(src.amount);
		vin_out_indices.push_back(src.real_output_in_tx_index);

		auto &outs = sources[i].outputs;
		std::vector<uint64_t> key_offsets;

		for(size_t j = 0; j < outs.size(); j++)
		{
			assert(mixin_count == outs.size());
			key_offsets.push_back(outs[j].first);

			xmr_pubkey tmp;
			memcpy(tmp.data, outs[j].second.dest.bytes, sizeof(tmp.data));
			sig_pubkeys.push_back(tmp);
		}

		key_offsets = cryptonote::absolute_output_offsets_to_relative(key_offsets);

		for(const auto &offset : key_offsets)
			vin_offsets.push_back(offset);

		xmr_pubkey pubkey;
		xmr_derivation derivation;
		xmr_pubkey eph_pubkey;

		memcpy(pubkey.data, src.real_out_tx_key.data, sizeof(pubkey.data));
		xmr_generate_key_derivation(&pubkey, &m_account.sec_viewkey, &derivation);
		xmr_derive_public_key(&derivation, src.real_output_in_tx_index, &m_account.pub_spendkey, &eph_pubkey);

		sig_indices.push_back(src.real_output);
		derivations.push_back(derivation);
		vin_eph_pubkeys.push_back(eph_pubkey);
	}

	std::vector<xmr_key_image> key_images;
	key_images.resize(vin_count);
	if(wire_xmr_generate_tx_vin(&m_device, vin_amounts.data(), (uint8_t *) derivations.data(), (uint8_t *) vin_eph_pubkeys.data(),
			vin_out_indices.data(), vin_count, vin_offsets.data(), mixin_count, construction_id, m_session_key, (uint8_t *) key_images.data()) != WIRE_SUCCESS)
	{
		TLOG("Failed: wire_xmr_generate_tx_vin.\n");
		return false;
	}

	for(size_t i = 0; i < vin_count; i++)
	{
		cryptonote::txin_to_key input;
		input.amount = vin_amounts[i];
		memcpy(input.k_image.data, key_images[i].data, sizeof(input.k_image.data));
		for(const cryptonote::tx_source_entry::output_entry &output : sources[i].outputs)
		{
			input.key_offsets.push_back(output.first);
		}

		input.key_offsets = cryptonote::absolute_output_offsets_to_relative(input.key_offsets);
		tx.vin.push_back(input);
	}

	std::vector<xmr_pubkey> outkeys;
	outkeys.resize(vout_count);

	if(wire_xmr_generate_tx_vout(&m_device, vout_amounts.data(), vout_indices.data(), vout_count, construction_id,
			m_session_key, (uint8_t *) outkeys.data()) != WIRE_SUCCESS)
	{
		TLOG("Failed: wire_xmr_generate_tx_vout.\n");
		return false;
	}

	for(size_t i = 0; i < vout_count; i++)
	{
		cryptonote::tx_out out;
		out.amount = shuffled_dests[i].amount;
		cryptonote::txout_to_key outkey;
		memcpy(outkey.key.data, outkeys[i].data, sizeof(outkey.key.data));
		out.target = outkey;
		tx.vout.push_back(out);
	}

	uint8_t *payment_id = nullptr;
	size_t payment_id_size = 0;

	switch(pid_type)
	{
	default:
	case payment_id_type::none:
		break;
	case payment_id_type::normal:
		payment_id_size = 32;
		payment_id = (uint8_t *) pid.data;
		break;

	case payment_id_type::encrypted:
		payment_id_size = 8;
		payment_id = (uint8_t *) pid.data;
		break;
	}

	xmr_hash prefix_hash;
	std::vector<uint8_t> extra_bytes;
	extra_bytes.resize(68);
	size_t extra_bytes_length = 0;

	if(wire_xmr_generate_tx_extra(&m_device, payment_id, payment_id_size, prefix_hash.data, extra_bytes.data(),
		&extra_bytes_length, construction_id, m_session_key) != WIRE_SUCCESS)
	{
		TLOG("Failed: wire_xmr_generate_tx_extra.\n");
		return false;
	}

	if(extra_bytes_length == 0)
		return false;

	extra_bytes.resize(extra_bytes_length);
	tx.extra = extra_bytes;

	crypto::hash expected_prefix_hash;
    cryptonote::get_transaction_prefix_hash(tx, expected_prefix_hash);

    if(memcmp(prefix_hash.data, expected_prefix_hash.data, sizeof(prefix_hash.data)) != 0)
    {
    	TLOG("Failed: transport error, invalid tx prefix hash.\n");
    	return false;
    }

	std::vector<uint8_t> sig_streams;
	std::vector<xmr_pubkey> sig_actual_pubkeys;
	std::vector<ec_scalar> sig_sums;
	std::vector<std::vector<xmr_signature>> signatures;

	sig_sums.resize(vin_count);
	size_t length_per_stream = xmr_get_stream_size(mixin_count);
	sig_streams.resize(length_per_stream * vin_count);

	for (size_t i = 0; i < vin_count; i++)
	{
		signatures.push_back(std::vector<xmr_signature>());
		auto &sigs = signatures.back();
		sigs.resize(mixin_count);

		size_t out_index = sig_indices[i];
		const xmr_pubkey *pubkeys = (xmr_pubkey *) sig_pubkeys.data() + (i * mixin_count);
		xmr_generate_ring_signature_stream(&prefix_hash, &key_images[i], pubkeys,
					mixin_count, out_index, sig_streams.data() + (i * length_per_stream), length_per_stream, sigs.data(), &sig_sums[i]);
		sig_actual_pubkeys.push_back(pubkeys[out_index]);
	}

	std::vector<xmr_signature> real_sigs;
	real_sigs.resize(vin_count);

	if(wire_xmr_generate_tx_signature(&m_device, sig_streams.data(), length_per_stream, (uint8_t *) derivations.data(),
			(uint8_t *) sig_sums.data(), vin_out_indices.data(), (uint8_t *) sig_actual_pubkeys.data(), vin_count,
			construction_id, m_session_key, (uint8_t *) real_sigs.data()) != WIRE_SUCCESS)
	{
		TLOG("Failed: wire_xmr_generate_signature.\n");
		return false;
	}


	tx.signatures.clear();
	for(size_t i = 0; i < vin_count; i++)
	{
		tx.signatures.push_back(std::vector<crypto::signature>());
		auto &sigs = tx.signatures.back();
		for(size_t j = 0; j < mixin_count; j++)
		{
			crypto::signature sig;
			if(j == sig_indices[i])
			{
				memcpy(sig.c.data, real_sigs[i].c.data, sizeof(sig.c.data));
				memcpy(sig.r.data, real_sigs[i].r.data, sizeof(sig.r.data));
			}
			else
			{
				auto &fake_sigs = signatures[i];
				memcpy(sig.c.data, fake_sigs[j].c.data, sizeof(sig.c.data));
				memcpy(sig.r.data, fake_sigs[j].r.data, sizeof(sig.r.data));
			}

			sigs.push_back(sig);
		}
	}

	return true;
}

//-------------------------------------------------------------------------------------------------
const tm trezor::get_timestamp() const
{
#if 1
	tm timestamp = {};
	timestamp.tm_year = 2016 - 1900;
	timestamp.tm_mon = 0;    // january
	timestamp.tm_mday = 28;  // 28th
#else
	tm timestamp = {};
	timestamp.tm_year = 2014 - 1900;
	timestamp.tm_mon = 1;
	timestamp.tm_mday = 1;
#endif
	return timestamp;
}

//-------------------------------------------------------------------------------------------------
bool trezor::get_last_account(cryptonote::account_keys &account) const
{
	if(!m_account_initialized)
		return false;
	copy_address_to_account_keys(account);
	return true;
}

//-------------------------------------------------------------------------------------------------
bool trezor::is_connected() const
{
	CRITICAL_REGION_LOCAL(m_device_lock);
	return wire_device_available(&m_device);
}

//-------------------------------------------------------------------------------------------------
bool trezor::reconnect()
{
	CRITICAL_REGION_LOCAL(m_device_lock);
	if(is_connected())
		return true;

	if(!m_account_initialized)
		return false;

	if(m_features != nullptr)
	{
		free(m_features);
		m_features = nullptr;
	}

	wire_device_close(&m_device);
	if(!initialize())
	{
		wire_device_close(&m_device);
		return false;
	}

	if(!get_session_key(true))
	{
		wire_device_close(&m_device);
		return false;
	}

	wire_set_passphrase_function(m_default_passphrase_function);

	xmr_account account = {};
	if(wire_xmr_request_viewkey(&m_device, false, nullptr, m_account_index, m_session_key, account.sec_viewkey.data,
			account.pub_spendkey.data) != WIRE_SUCCESS)
	{
		wire_device_close(&m_device);
		TLOG("Failed: wire_xmr_request_viewkey on reconnect.\n");
		return false;
	}


	xmr_public_key(&account.sec_viewkey, &account.pub_viewkey);
	if(memcmp(&account, &m_account, sizeof(account)) != 0)
	{
		wire_clear_session(&m_device);
		wire_device_close(&m_device);
		TLOG("Failed: reconnect, inserted hw is different.\n");
		return false;
	}

	return true;
}

//-------------------------------------------------------------------------------------------------
void trezor::copy_address_to_account_keys(cryptonote::account_keys &account) const
{
	memset(account.m_spend_secret_key.data, 0, sizeof(account.m_spend_secret_key.data));
	memcpy(account.m_view_secret_key.data, m_account.sec_viewkey.data, sizeof(account.m_view_secret_key.data));

	cryptonote::account_public_address &address = account.m_account_address;

	memcpy(address.m_spend_public_key.data, m_account.pub_spendkey.data, sizeof(address.m_spend_public_key.data));
	memcpy(address.m_view_public_key.data, m_account.pub_viewkey.data, sizeof(address.m_view_public_key.data));
}

//-------------------------------------------------------------------------------------------------
// FIXME: remove this.
std::string trezor::m_password;
int trezor::passphrase_function(char *data, size_t length)
{
	strncpy(data, m_password.c_str(), length);
	data[length - 1] = '\0';
	return 0;
}
}
