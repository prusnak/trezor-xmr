#ifndef SRC_TREZOR_TREZORWALLET_H_
#define SRC_TREZOR_TREZORWALLET_H_

#include "wallet/wallet2.h"
#include "trezor.h"

namespace kokko
{
class trezorwallet: public tools::wallet2
{
public:
	trezorwallet(bool testnet = false, bool restricted = false);
	virtual ~trezorwallet();

	static trezor &get_hw() { return m_hw; }

protected:
    virtual void get_key_images(const std::vector<size_t> &outs, const crypto::public_key &tx_pub_key,
    		std::vector<cryptonote::keypair> &ephemerals, std::vector<crypto::key_image> &key_images);

    virtual bool store_keys(const std::string& keys_file_name, const std::string& password, bool watch_only = false);
    virtual bool load_keys(const std::string& keys_file_name, const std::string& password);

private:
    static trezor m_hw;
};
}
#endif
