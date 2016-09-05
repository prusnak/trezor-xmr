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

#include "wallet/wallet_errors.h"
#include "wallet/wallet2.h"

#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>

#include <boost/utility/value_init.hpp>
#include "include_base_utils.h"
#include "trezorwallet.h"
using namespace epee;

#include "rpc/core_rpc_server_commands_defs.h"
#include "misc_language.h"
#include "cryptonote_core/cryptonote_basic_impl.h"
#include "common/boost_serialization_helper.h"
#include "profile_tools.h"
#include "crypto/crypto.h"
#include "serialization/binary_utils.h"
#include "cryptonote_protocol/blobdatatype.h"
#include "mnemonics/electrum-words.h"
#include "common/dns_utils.h"
#include "common/util.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include <string>

namespace kokko
{
//----------------------------------------------------------------------------------------------------
trezor trezorwallet::m_hw;

//----------------------------------------------------------------------------------------------------
trezorwallet::trezorwallet(bool testnet, bool restricted) : wallet2(testnet, restricted)
{
}

//----------------------------------------------------------------------------------------------------
trezorwallet::~trezorwallet()
{
}

//----------------------------------------------------------------------------------------------------
void trezorwallet::get_key_images(const std::vector<size_t> &outs, const crypto::public_key &tx_pub_key,
		std::vector<cryptonote::keypair> &ephemerals, std::vector<crypto::key_image> &key_images)
{
	ephemerals.clear();
	key_images.clear();

	bool r = trezorwallet::get_hw().get_key_images(key_images, ephemerals, tx_pub_key, outs);
	THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, "hw could not generate key images.");
}

//----------------------------------------------------------------------------------------------------
bool trezorwallet::store_keys(const std::string& keys_file_name, const std::string& password, bool watch_only)
{
	return true;
}

//----------------------------------------------------------------------------------------------------
bool trezorwallet::load_keys(const std::string& keys_file_name, const std::string& password)
{
	cryptonote::account_keys account;
	bool r = trezorwallet::get_hw().get_last_account(account);
	THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, "hw account not initialized.");

	clear();
	std::string base_file_name = string_tools::cut_off_extension(keys_file_name);
	prepare_file_names(base_file_name);

	m_account.create_from_viewkey(account.m_account_address, account.m_view_secret_key, trezorwallet::get_hw().get_timestamp());

	m_account_public_address = account.m_account_address;
	m_watch_only = false;

	r = tools::verify_keys(m_account.get_keys().m_view_secret_key,  m_account.get_keys().m_account_address.m_view_public_key);
	THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, "hw account view keys are invalid.");
	return true;
}

}
