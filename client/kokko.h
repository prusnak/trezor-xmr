#if !defined(__KOKKO_H__)
#define __KOKKO_H__

#include <stdbool.h>

#include "crypto-xmr.h"
#include "hidapi.h"

#include "protobuf-c/types.pb-c.h"
#include "protobuf-c/protobuf-c.h"
#include "protobuf-c/messages.pb-c.h"
#include "protobuf-c/storage.pb-c.h"

#define WIRE_SUCCESS			0L
#define WIRE_ERROR				-1L
#define WIRE_BUFFER_TOO_SMALL	-2L
#define WIRE_INVALID_BUCKET		-3L
#define WIRE_INVALID_MESSAGE	-4L
#define WIRE_NO_RESPONSE		-5L
#define WIRE_STREAM_TOO_LONG	-6L

#define WIRE_REPORT_BUCKET_SIZE	64U
#define WIRE_MAX_ADDRESS_CHILD_DEPTH		1024U

#define WIRE_SESSION_KEY_LENGTH	64U
#define WIRE_MAX_STREAM_LENGTH	XMR_MAX_STREAM_LENGTH

typedef enum { HID_UNKNOWN, HID_V1, HID_V2} HID_VERSION;

typedef struct
{
	hid_device *dev;
	HID_VERSION ver;
} wire_device;

#ifdef __cplusplus
extern "C" {
#endif

typedef int(*wire_pin_function_t)(PinMatrixRequestType type, char *data, size_t length);
typedef int(*wire_passphrase_function_t)(char *pass, size_t length);
typedef int(*wire_display_success_function_t)(const char *data);
typedef int(*wire_display_failure_function_t)(const char *data);
typedef int(*wire_display_fingerprint_function_t)(const char *data);
typedef int(*wire_recovery_word_function_t)(char *word, size_t length);

int wire_device_open(wire_device *device);
int wire_device_close(wire_device *device);
bool wire_device_available(const wire_device *device);

wire_pin_function_t wire_set_pin_function(wire_pin_function_t func);
wire_passphrase_function_t wire_set_passphrase_function(wire_passphrase_function_t func);
wire_display_failure_function_t wire_set_failure_function(wire_display_failure_function_t func);
wire_display_success_function_t wire_set_success_function(wire_display_success_function_t func);
wire_display_fingerprint_function_t wire_set_display_fingerprint_function(wire_display_fingerprint_function_t func);
wire_recovery_word_function_t wire_set_recovery_word_function(wire_recovery_word_function_t func);

int wire_initialize(const wire_device *device, Features **features);
int wire_get_address(const wire_device *device, Address **address, const char *path, const char *coin_name, bool show_on_display);
int wire_firmware_update(wire_device *device, const char *file_path);
int wire_reset_device(const wire_device *device, const char *label, bool pin_protect, bool passphrase_protect, bool display_random, uint32_t strength);
int wire_wipe_device(const wire_device *device);
int wire_clear_session(const wire_device *device);
int wire_ping(const wire_device *device, const char *message, bool pin_protect, bool passphrase_protect, bool button_protect);

int wire_recover_device(const wire_device *device, const char *label, size_t word_count, bool pin_protect, bool passphrase_protect, bool verify_words);

int wire_xmr_request_session_key(const wire_device *device, uint8_t *session_key);
int wire_xmr_request_viewkey(const wire_device *device, bool display, const char *passphrase, size_t index, const uint8_t *session_key, uint8_t *view_key, uint8_t *pub_spend_key);

int wire_xmr_generate_key_image(const wire_device *device, const uint8_t *derivation, const uint8_t *eph_pub_keys, const uint64_t *indices,
	size_t count, const uint8_t *session_key, uint8_t *key_images);

int wire_xmr_generate_tx_signature(const wire_device *device, const uint8_t *streams, size_t stream_length, const uint8_t *derivations,
	const uint8_t *sums, const uint64_t *out_indices, const uint8_t *pubkeys, size_t sig_count,
	uint64_t tx_construction_id, const uint8_t *session_key, uint8_t *signatures);

int wire_xmr_generate_tx_init(const wire_device *device, uint64_t version, uint64_t unlock_time, uint32_t mixin, uint32_t vin_count, uint32_t vout_count,
	const uint8_t *addresses, size_t addresses_count, const uint8_t *session_key, uint8_t *tx_seckey, uint64_t *tx_construction_id);

int wire_xmr_generate_tx_vin(const wire_device *device, const uint64_t *amounts, const uint8_t *derivations, const uint8_t *eph_pubkeys, const uint64_t *out_indices,
	size_t vin_count, const uint64_t *offsets, size_t offset_count, uint64_t tx_construction_id, const uint8_t *session_key, uint8_t *key_images);

int wire_xmr_generate_tx_vout(const wire_device *device, const uint64_t *amounts, const int32_t *addr_indices, size_t vout_count,
	uint64_t tx_construction_id, const uint8_t *session_key, uint8_t *pubkeys);

int wire_xmr_generate_tx_extra(const wire_device *device, const uint8_t *payment_id, size_t payment_id_size, uint8_t *tx_prefix_hash,
	uint8_t *extra_bytes, size_t *extra_bytes_length, uint64_t tx_construction_id, const uint8_t *session_key);

int wire_xmr_get_debug_link_state(DebugLinkState **debug_link_state);

#ifdef __cplusplus
}
#endif

#endif
