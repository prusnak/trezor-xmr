#ifndef __XMR_STREAM_H__
#define __XMR_STREAM_H__

#include <stdint.h>

#include "KeccakNISTInterface.h"
#include "crypto-xmr.h"
#include "limits-xmr.h"

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 1)

#define TXOUT_TO_KEY_TAG					0x02
#define TXIN_TO_KEY_TAG 					0x02

#define TX_EXTRA_PADDING_MAX_COUNT          255
#define TX_EXTRA_NONCE_MAX_COUNT            255

#define TX_EXTRA_TAG_PADDING                0x00
#define TX_EXTRA_TAG_PUBKEY                 0x01
#define TX_EXTRA_NONCE                      0x02
#define TX_EXTRA_MERGE_MINING_TAG           0x03

#define TX_EXTRA_NONCE_PAYMENT_ID           0x00
#define TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID 0x01

#define XMR_ENCRYPTED_PAYMENT_ID_SIZE		8U
#define XMR_DEFAULT_PAYMENT_ID_SIZE			32U

#define XMR_ENCRYPTED_PAYMENT_ID_VERSION 	1U
#define XMR_DEFAULT_PAYMENT_ID_VERSION		0U

#define XMR_ADDRESS_CHECKSUM_SIZE			4U

#define XMR_PUBLIC_ADDRESS_BASE58_PREFIX 						18U
#define XMR_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX				19U
#define XMR_TESTNET_PUBLIC_ADDRESS_BASE58_PREFIX				53U
#define XMR_TESTNET_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX 	54U

enum
{
	TX_STEP_RESET = 0,
	TX_STEP_INIT = 1,
	TX_STEP_VIN = 2,
	TX_STEP_VOUT = 3,
	TX_STEP_EXTRA = 4,
	TX_STEP_SIG = 5,
	TX_STEP_INVALID = -1
};

typedef enum
{
	XMR_ADDR_DEFAULT = 0,
	XMR_ADDR_INTEGRATED_V1 = 1,
	XMR_ADDR_INTEGRATED_V2 = 2
} XMR_ADDR_TYPE;

typedef struct xmr_address_t
{
	xmr_pubkey spendkey;
	xmr_pubkey viewkey;
	uint32_t addr_type;

} xmr_address;

typedef struct xmr_account_t
{
	xmr_seckey sec_spendkey;
	xmr_seckey sec_viewkey;
	xmr_pubkey pub_spendkey;
	xmr_pubkey pub_viewkey;

} xmr_account;

typedef struct xmr_transaction_t
{
	uint64_t version;
	uint64_t unlock_time;

	hashState state;
	uint64_t id;
	size_t vin_count;
	size_t vout_count;
	size_t sig_count;
	size_t cur_vin_count;
	size_t cur_vout_count;
	size_t cur_sig_count;

	size_t mixin_count;

	int32_t current_step;

	uint64_t input_total;
	uint64_t output_total;
	uint64_t change_total;

	size_t tx_size;

	size_t dest_addresses_count;
	xmr_address dest_addresses[XMR_MAX_OUT_ADDRESSES];
	uint64_t dest_amount[XMR_MAX_OUT_ADDRESSES];
	xmr_derivation dest_derivation[XMR_MAX_OUT_ADDRESSES];
    	xmr_derivation acct_derivation;

	xmr_seckey tx_seckey;
	xmr_pubkey tx_pubkey;

	xmr_hash tx_prefix_hash;

	xmr_hash payment_id;
	uint32_t payment_id_ver;
	bool has_payment_id;

	uint64_t fee;
	bool testnet;

} xmr_transaction;

#pragma pack(pop)

void xmr_encode_varint(uint64_t value, uint8_t **ptr, size_t *count);
void xmr_add_tx_pubkey_to_extra(const xmr_pubkey *tx_pubkey, uint8_t *extra, size_t *count);
void xmr_add_payment_id_to_extra(const uint8_t *payment_id, size_t payment_id_size,
		const xmr_pubkey *pubkey, const xmr_seckey *seckey, uint8_t *extra, size_t *count);
bool xmr_get_b58_address(bool integrated, bool testnet, const xmr_address *address,
		const xmr_hash *payment_id, char *encoded_addr);

#ifdef __cplusplus
}
#endif

#endif
