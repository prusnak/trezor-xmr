#if !defined(__TREZOR_H__)
#define __TREZOR_H__

#include "cryptonote_core/account.h"
#include "cryptonote_core/cryptonote_format_utils.h"
#include "stream.h"
#include "kokko.h"

namespace kokko
{
class trezor
{
public:
	trezor();
	~trezor();

	enum payment_id_type
	{
		none,
		normal,
		encrypted
	};

	bool get_account(bool display, cryptonote::account_keys &account, uint32_t index, const std::string &password);
	bool get_last_account(cryptonote::account_keys &account) const;

	bool get_key_images(std::vector<crypto::key_image> &key_images, std::vector<cryptonote::keypair> &ephemerals,
			const crypto::public_key &tx_pubkey, const std::vector<size_t> &outs);

	bool generate_tx(cryptonote::transaction &tx, const std::vector<cryptonote::tx_source_entry> &sources, const std::vector<cryptonote::tx_destination_entry> &shuffled_dests,
			uint64_t unlock_time, uint64_t version, trezor::payment_id_type pid_type, const crypto::hash &pid);

	bool display_address();

	std::string get_address() const;
	const tm get_timestamp() const;

	bool initialize();
	void shutdown();

	bool has_password_protection();
	bool is_connected() const;
	bool reconnect();

private:
	bool get_session_key(bool renew = false);
	Features *get_features();
	void copy_address_to_account_keys(cryptonote::account_keys &account) const;

	static bool check_ring_signatures(const cryptonote::transaction &tx);

private:
	uint8_t m_session_key[64];
	Features *m_features;

	xmr_account m_account;
	uint32_t m_account_index;

	bool m_session_initialized;
	bool m_account_initialized;

	static std::string m_password;
	mutable epee::critical_section m_device_lock;
	wire_device m_device;

	wire_passphrase_function_t m_default_passphrase_function;

private:
	static int passphrase_function(char *data, size_t length);
};

}

#endif
