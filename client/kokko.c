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
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#include "kokko.h"
#include "crypto-xmr.h"
#include "crypto-ops.h"
#include "keccak.h"
#include "limits-xmr.h"
#include "stream.h"
#include "key_exchange.h"
#include "random.h"
#include "log.h"
#include "hidapi.h"

#include "terminal.h"

#if defined(_WIN32)
#define sleep_ms(ms) Sleep(ms)
#else
#define sleep_ms(ms) usleep(ms * 1000)
#endif

static void random_buffer(void *result, size_t n) 
{
    // Note: you can use your own rng here.
	generate_random_bytes_not_thread_safe(n, result);
}

#define MSG_OUT_SIZE            (32 * 1024)
#define MSG_TIMEOUT             5000L

#define MSG_ID(d) ((d[3] << 8) + d[4])
#define MSG_LEN(d) ((d[5] << 24) + (d[6] << 16) + (d[7] << 8) + d[8])

#define WIRE_MAX_KEYIMAGE_GROUP     10      // max 48
#define WIRE_MAX_VIN_GROUP          10      // max 48
#define WIRE_MAX_VOUT_GROUP         10      // max 48
#define WIRE_MAX_SIG_GROUP          5       // max 10

const int idVendor = 0x534C;
const int idProduct = 0x0001;

///////////////////////////////////////////////////////////////////////////////
// internal variables
static const char *_msg_tag = "?##";
static const size_t _msg_tag_size = 3;
static const size_t _msg_header_size = 9;

static int default_pin_function(PinMatrixRequestType type, char *data, size_t length);
static int default_passphrase_function(char *data, size_t length);
static int default_display_failure_function(const char *data);
static int default_display_success_function(const char *data);
static int default_display_fingerprint_function(const char *data);
static int default_recovery_word_function(char *data, size_t length);

static wire_display_fingerprint_function_t _display_fingerprint_function = default_display_fingerprint_function;
static wire_pin_function_t _pin_function = default_pin_function;
static wire_passphrase_function_t _passphrase_function = default_passphrase_function;
static wire_display_failure_function_t _failure_function = default_display_failure_function;
static wire_display_success_function_t _success_function = default_display_success_function;
static wire_recovery_word_function_t _recovery_word_function = default_recovery_word_function;

///////////////////////////////////////////////////////////////////////////////
// helper functions
static bool handle_error(const wire_device *device, int error)
{
    const wchar_t *message = hid_error(device->dev);
    return false;
}

inline uint8_t _ch(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    return 0;
}

static void hex_to_data(const char *data, uint8_t *dest)
{   
    if (strlen(data) % 2 != 0)
    {
        dest[0] = '\0';
        return;
    }

    size_t len = strlen(data) / 2; // only groups of two
    for (size_t i = 0; i < len; i++)
    {
        *(dest++) = (_ch(*data) << 4) | _ch(data[1]);
        data += 2;
    }

    *dest = '\0';
}

static void data_to_hex(const uint8_t *data, uint32_t len, char *str)
{
    static const char *digits = "0123456789ABCDEF";
    uint32_t i;
    for (i = 0; i < len; i++) 
    {
        str[i * 2] = digits[(data[i] >> 4) & 0x0F];
        str[i * 2 + 1] = digits[data[i] & 0x0F];
    }

    str[len * 2] = 0;
}

///////////////////////////////////////////////////////////////////////////////
// hid functions
static void hid_enable_uart_clear_fifo(const wire_device *device)
{
    const uint8_t uart[] = { 0x41, 0x01 }; // enable UART
    const uint8_t txrx[] = { 0x43, 0x03 }; // purge TX/RX FIFOs

    assert(device != NULL);
    if(device->dev == NULL)
        return;

    hid_send_feature_report(device->dev, uart, 2);
    hid_send_feature_report(device->dev, txrx, 2);
}

// FIXME: ugly fix for usb report length change introduced in firmware >= v1.3.6
// Previous version had a constant report length of 64 bytes. With the new version
// the bootloader still uses 64 bytes but for everything else is now 65.
static HID_VERSION hid_get_version(const wire_device *device)
{
    assert(device != NULL);
    if(device->dev == NULL)
    	return HID_UNKNOWN;

    uint8_t data[65];
    memset(data, 0xff, sizeof(data));
    data[0] = 0x00;
    data[1] = 0x3f;
    int written = hid_write(device->dev, data, 65);
    if(written == 65)
    	return HID_V2;

    memset(data, 0xff, sizeof(data));
    data[0] = 0x3f;
    written = hid_write(device->dev, data, 64);
    if(written == 64)
    	return HID_V1;

    return HID_UNKNOWN;
}

int wire_device_open(wire_device *device)
{
    hid_init();

    assert(device != NULL);
	if (device->dev != NULL)
	{
		return WIRE_SUCCESS;
	}

    device->dev = hid_open(idVendor, idProduct, NULL);
    if (device->dev == NULL)
    {
        return WIRE_ERROR;
    }

    device->ver = hid_get_version(device);
    if(device->ver == HID_UNKNOWN)
    	return WIRE_ERROR;

    hid_enable_uart_clear_fifo(device);
    return WIRE_SUCCESS;
}

int wire_device_close(wire_device *device)
{
    assert(device != NULL);
    if (device->dev == NULL)
        return WIRE_ERROR;

    hid_close(device->dev);
    device->dev = NULL;

    // hid_exit();

    return WIRE_SUCCESS;
}

bool wire_device_available(const wire_device *device)
{
    assert(device != NULL);
    if (device->dev == NULL)
        return false;

    hid_set_nonblocking(device->dev, 1);
    uint8_t data[64];
    int res = hid_read(device->dev, data, sizeof(data));
    hid_set_nonblocking(device->dev, 0);

    return res >= 0;
}

int hid_device_nonblocking(const wire_device *device, bool nonblocking)
{
    assert(device != NULL);
    if (device->dev == NULL)
        return WIRE_ERROR;

    hid_set_nonblocking(device->dev, nonblocking ? 1 : 0);
    return WIRE_SUCCESS;
}

int hid_device_send(const wire_device *device, const uint8_t *data, size_t length)
{
    assert(data != NULL);
    assert(length != 0);
    assert(device != NULL);

    if (device->dev == NULL)
    	return WIRE_ERROR;

    if(length > WIRE_REPORT_BUCKET_SIZE)
    	return WIRE_ERROR;

#if defined(RAW_USB_DUMP)
    size_t len = length;
    size_t offset = 0;
    TLOG(">> USBS: ");
    while(len > 0)
    {
        char str[256];
        const size_t group = 64;
        data_to_hex(data + offset, group, str);
        offset += group;
        len -= group;
        TLOG("\t%s\n", str);
    }
#endif

    int res = 0;
    // FIXME: ugly fix to support the bucket size change with >= v1.3.6 firmware
    if(device->ver == HID_V1)
    {
    	res = hid_write(device->dev, data, length);
    }
    else if(device->ver == HID_V2)
    {
		uint8_t data2[WIRE_REPORT_BUCKET_SIZE + 1];
		memset(data2, 0, sizeof(data2));
		size_t datalen = length >= WIRE_REPORT_BUCKET_SIZE ? WIRE_REPORT_BUCKET_SIZE : length;
		memcpy(data2 + 1U, data, datalen);
		res = hid_write(device->dev, data2, sizeof(data2));
    }
    else
    {
    	// shouldn't happen
    	return WIRE_ERROR;
    }

    handle_error(device, res);
    return res > 0 ? WIRE_SUCCESS : WIRE_ERROR;
}

int hid_device_receive(const wire_device *device, uint8_t *data, size_t *length, bool usetimeout)
{
    assert(data != NULL);
    assert(length != NULL);
    assert(device != NULL);

    if (device->dev == NULL)
    	return WIRE_ERROR;

    int res = WIRE_ERROR; 
    if (usetimeout)
        res = hid_read_timeout(device->dev, data, *length, MSG_TIMEOUT);
    else
        res = hid_read(device->dev, data, *length);

#if defined(RAW_USB_DUMP)
    size_t len = *length;
    size_t offset = 0;
    TLOG(">> USBR: ");
    while(len > 0)
    {
        char str[256];
        const size_t group = 64;
        data_to_hex(data + offset, group, str);
        offset += group;
        len -= group;
        TLOG("\t%s\n", str);
    }
#endif

    *length = res > 0 ? res : 0;
    return res < 0 ? WIRE_ERROR : WIRE_SUCCESS;
    
}

int hid_device_collect_response(const wire_device *device, uint8_t *data, size_t *length, uint16_t *resp_id, size_t *resp_length)
{
    size_t total = 0;
    bool header = true;

    uint16_t rid = 0;
    uint32_t rlen = 0;

    assert(data);
    assert(length);
    assert(resp_id);
    assert(resp_length);
    assert(*length >= WIRE_REPORT_BUCKET_SIZE);
    assert(device != NULL);

    if(device->dev == NULL)
    	return WIRE_ERROR;
    hid_device_nonblocking(device, false);

    const int max_loop = 512;
    #define RETURN_ERROR(_e, _n) \
        do { \
            hid_device_nonblocking(device, false); \
            TLOG("hid_device_collect_response() error: %ld [%d]\n", _e, _n); \
            return _e; \
        } while (0); \

    bool found = false;
    for (int i = 0; i < max_loop && !found; i++)
    {
        uint8_t bucket[WIRE_REPORT_BUCKET_SIZE];
        size_t len = WIRE_REPORT_BUCKET_SIZE;

        if (hid_device_receive(device, bucket, &len, false) != WIRE_SUCCESS)
        {
            RETURN_ERROR(WIRE_ERROR, 1);
        }

        if (header)
        {
            if (len <= _msg_tag_size)
            {
                if (i == max_loop - 1)
                {
                    RETURN_ERROR(WIRE_INVALID_MESSAGE, 2);
                }
                continue;
            }

            header = false;
            if (memcmp(bucket, _msg_tag, _msg_tag_size) != 0)
            {
                RETURN_ERROR(WIRE_INVALID_MESSAGE, 3);
            }
            rid = MSG_ID(bucket);
            rlen = MSG_LEN(bucket);

            total = len;
            memcpy(data, bucket, total);
            if ((total - _msg_header_size) >= rlen)
            {
                found = true;
                break;
            }
        }
        else
        {
            if (len <= 1L)
            {
                if (total > 0)
                    break;

                RETURN_ERROR(WIRE_INVALID_MESSAGE, 4);
            }

            if (bucket[0] != '?')
            {
                RETURN_ERROR(WIRE_INVALID_BUCKET, 5);
            }
            const int add = WIRE_REPORT_BUCKET_SIZE - 1;
            memcpy(data + total, bucket + 1, add);
            total += add;

            if (total >= *length)
            {
                RETURN_ERROR(WIRE_BUFFER_TOO_SMALL, 6);
            }

            if ((total - _msg_header_size) >= rlen)
            {
                found = true;
                break;
            }
        }
    }

    *length = total;
    *resp_id = rid;
    *resp_length = rlen;

    return WIRE_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// message
enum Direction { INCOMING, OUTGOING };
enum Type { NORMAL, DEBUG, };
typedef struct Map_t
{
    enum Type type;
    enum Direction dir;
    uint16_t id;
    int(*process_function)(const wire_device *device, void **, uint8_t *data, size_t *length, uint16_t *resp_id, size_t *resp_length);
} Map;

#define HANDLER_FUNC(_f) process_message_##_f
#define MESSAGE_TYPE(_m) MESSAGE_TYPE__MessageType_##_m

#define INCOMING_MESSAGE(_f)      { NORMAL, INCOMING, MESSAGE_TYPE(_f), HANDLER_FUNC(_f) }
#define INCOMING_MESSAGE_NULL(_f) { NORMAL, INCOMING, MESSAGE_TYPE(_f), NULL   }

#define OUTGOING_MESSAGE(_f)      { NORMAL, OUTGOING, MESSAGE_TYPE(_f), HANDLER_FUNC(_f) }
#define OUTGOING_MESSAGE_NULL(_f) { NORMAL, OUTGOING, MESSAGE_TYPE(_f), NULL   }

#define DECLARE_PROCESS_FUNCTION(_f) \
		static int HANDLER_FUNC(_f)(const wire_device *device, void **procdata, uint8_t *data, size_t *length, uint16_t *resp_id, size_t *resp_length); \

#define DEFINE_PROCESS_FUNCTION(_f) \
        static int HANDLER_FUNC(_f)(const wire_device *device, void **procdata, uint8_t *data, size_t *length, uint16_t *resp_id, size_t *resp_length) \

DECLARE_PROCESS_FUNCTION(Success)
DECLARE_PROCESS_FUNCTION(Failure)
DECLARE_PROCESS_FUNCTION(Entropy)
DECLARE_PROCESS_FUNCTION(PublicKey)
DECLARE_PROCESS_FUNCTION(Features)
DECLARE_PROCESS_FUNCTION(PinMatrixRequest)
DECLARE_PROCESS_FUNCTION(CipheredKeyValue)
DECLARE_PROCESS_FUNCTION(ButtonRequest)
DECLARE_PROCESS_FUNCTION(Address)
DECLARE_PROCESS_FUNCTION(EntropyRequest)
DECLARE_PROCESS_FUNCTION(MessageSignature)
DECLARE_PROCESS_FUNCTION(SignedIdentity)
DECLARE_PROCESS_FUNCTION(EncryptedMessage)
DECLARE_PROCESS_FUNCTION(DecryptedMessage)
DECLARE_PROCESS_FUNCTION(PassphraseRequest)
DECLARE_PROCESS_FUNCTION(WordRequest)
DECLARE_PROCESS_FUNCTION(XmrRequestSessionKeyAck)
DECLARE_PROCESS_FUNCTION(XmrRequestViewKeyAck)
DECLARE_PROCESS_FUNCTION(XmrGenerateKeyImageAck)
DECLARE_PROCESS_FUNCTION(XmrGenerateSignatureAck)
DECLARE_PROCESS_FUNCTION(XmrGenerateTxInitAck)
DECLARE_PROCESS_FUNCTION(XmrGenerateTxExtraAck)
DECLARE_PROCESS_FUNCTION(XmrGenerateTxVinAck)
DECLARE_PROCESS_FUNCTION(XmrGenerateTxVoutAck)

static const Map MessageMap[] =
{
    // OUTGOING messages
    OUTGOING_MESSAGE_NULL(Initialize),
    OUTGOING_MESSAGE_NULL(GetFeatures),
    OUTGOING_MESSAGE_NULL(Ping),
    OUTGOING_MESSAGE_NULL(ChangePin),
    OUTGOING_MESSAGE_NULL(WipeDevice),
    OUTGOING_MESSAGE_NULL(FirmwareErase),
    OUTGOING_MESSAGE_NULL(FirmwareUpload),
    OUTGOING_MESSAGE_NULL(GetEntropy),
    OUTGOING_MESSAGE_NULL(GetPublicKey),
    OUTGOING_MESSAGE_NULL(LoadDevice),
    OUTGOING_MESSAGE_NULL(ResetDevice),
    OUTGOING_MESSAGE_NULL(SignTx),
    OUTGOING_MESSAGE_NULL(PinMatrixAck),
    OUTGOING_MESSAGE_NULL(Cancel),
    OUTGOING_MESSAGE_NULL(TxAck),
    OUTGOING_MESSAGE_NULL(CipherKeyValue),
    OUTGOING_MESSAGE_NULL(ClearSession),
    OUTGOING_MESSAGE_NULL(ApplySettings),
    OUTGOING_MESSAGE_NULL(ButtonAck),
    OUTGOING_MESSAGE_NULL(GetAddress),
    OUTGOING_MESSAGE_NULL(EntropyAck),
    OUTGOING_MESSAGE_NULL(SignMessage),
    OUTGOING_MESSAGE_NULL(SignIdentity),
    OUTGOING_MESSAGE_NULL(VerifyMessage),
    OUTGOING_MESSAGE_NULL(EncryptMessage),
    OUTGOING_MESSAGE_NULL(DecryptMessage),
    OUTGOING_MESSAGE_NULL(PassphraseAck),
    OUTGOING_MESSAGE_NULL(EstimateTxSize),
    OUTGOING_MESSAGE_NULL(RecoveryDevice),
    OUTGOING_MESSAGE_NULL(WordAck),
    OUTGOING_MESSAGE_NULL(XmrRequestSessionKey),
    OUTGOING_MESSAGE_NULL(XmrRequestViewKey),

    // INCOMING messages
    INCOMING_MESSAGE(Success),
    INCOMING_MESSAGE(Failure),
    INCOMING_MESSAGE(Entropy),
    INCOMING_MESSAGE(PublicKey),
    INCOMING_MESSAGE(Features),
    INCOMING_MESSAGE(PinMatrixRequest),
    INCOMING_MESSAGE_NULL(TxRequest),
    INCOMING_MESSAGE(CipheredKeyValue),
    INCOMING_MESSAGE(ButtonRequest),
    INCOMING_MESSAGE(Address),
    INCOMING_MESSAGE(EntropyRequest),
    INCOMING_MESSAGE(MessageSignature),
    INCOMING_MESSAGE(SignedIdentity),
    INCOMING_MESSAGE(EncryptedMessage),
    INCOMING_MESSAGE(DecryptedMessage),
    INCOMING_MESSAGE(PassphraseRequest),
    INCOMING_MESSAGE_NULL(TxSize),
    INCOMING_MESSAGE(WordRequest),
    INCOMING_MESSAGE(XmrRequestSessionKeyAck),
    INCOMING_MESSAGE(XmrRequestViewKeyAck),
    INCOMING_MESSAGE(XmrGenerateKeyImageAck),
    INCOMING_MESSAGE(XmrGenerateSignatureAck),
    INCOMING_MESSAGE(XmrGenerateTxInitAck),
    INCOMING_MESSAGE(XmrGenerateTxExtraAck),
    INCOMING_MESSAGE(XmrGenerateTxVinAck),
    INCOMING_MESSAGE(XmrGenerateTxVoutAck),
};

static int pack_header(uint8_t *data, size_t length, uint16_t msg_id, uint32_t msg_length)
{
    assert(length > _msg_header_size);
    memcpy(data, _msg_tag, _msg_tag_size);
    int index = _msg_tag_size;

    #define append(_b) data[index++] = ((_b) & 0xFFU)

    append(msg_id >> 8);
    append(msg_id >> 0);
    append(msg_length >> 24);
    append(msg_length >> 16);
    append(msg_length >> 8);
    append(msg_length >> 0);

    return _msg_header_size;
}

static int process_response(const wire_device *device, void **procdata, uint8_t *data, size_t *length, uint16_t *resp_id, size_t *resp_length)
{
    assert(data != NULL);
    assert(length != NULL);
    assert(resp_id != NULL);
    assert(resp_length != NULL);
    assert(device != NULL);

    size_t count = sizeof(MessageMap) / sizeof(MessageMap[0]);
    for (size_t i = 0; i < count; i++)
    {
        Map item = MessageMap[i];
        if (item.id == *resp_id)
        {
            if (item.process_function != NULL && item.process_function(device, procdata, data, length, resp_id, resp_length) != WIRE_SUCCESS)
                return WIRE_ERROR;
            break;
        }
    }

    return WIRE_SUCCESS;
}

static int default_pin_function(PinMatrixRequestType type, char *data, size_t length)
{
    switch (type)
    {
        default:
        case PIN_MATRIX_REQUEST_TYPE__PinMatrixRequestType_Current:
            printf("Enter PIN: ");
            break;
        case PIN_MATRIX_REQUEST_TYPE__PinMatrixRequestType_NewFirst:
            printf("Enter new PIN: ");
            break;
        case PIN_MATRIX_REQUEST_TYPE__PinMatrixRequestType_NewSecond:
            printf("Confirm new PIN: ");
            break;
    }

	ssize_t read = read_console(true, data, length);
    return read >= 0 ? WIRE_SUCCESS : WIRE_ERROR;
}

static int default_passphrase_function(char *data, size_t length)
{
    for(;;)
    {
    	char first[128];
    	char second[128];
    	printf("Password required: ");
    	ssize_t read = read_console(true, first, sizeof(first));
    	if(read < 0)
    		return WIRE_ERROR;
    	printf("Confirm password : ");
    	read = read_console(true, second, sizeof(second));
    	if(read < 0)
    		return WIRE_ERROR;

    	if(strcmp(first, second) != 0)
		{
			printf("[Password Mismatch]\n");
			continue;
		}

    	strncpy(data, first, length);
    	data[length - 1] = '\0';

    	break;
    }

    return WIRE_SUCCESS;
}

static int default_recovery_word_function(char *data, size_t length)
{
    printf("Enter word required: ");
	ssize_t read = read_console(false, data, length);
    return read >= 0 ? WIRE_SUCCESS : WIRE_ERROR;
}

static int default_display_failure_function(const char *data)
{
    printf("Failure: %s\n", data);
    return WIRE_SUCCESS;
}

static int default_display_success_function(const char *data)
{
    // printf("Success: %s\n", data);
    return WIRE_SUCCESS;
}

static int default_display_fingerprint_function(const char *data)
{
    printf("Fingerprint: %s\n", data);
    return WIRE_SUCCESS;
}

static int expand_address_path(const char *path, uint32_t *expanded, size_t *count)
{
    assert(expanded != NULL);
    assert(count != NULL);
    assert(*count >= 1);

    char *data = (char *) malloc(strlen(path) + 1);
    strcpy(data, path);
    const char *s = path;
    char *d = data;
    do { while (isspace(*s)) { s++; } } while (*d++ = *s++);

    if (strlen(data) == 0)
    {
        free(data);
        return WIRE_SUCCESS;
    }

    size_t index = 0;
    char *pch = strtok(data, "/");
    while (pch != NULL)
    {
        size_t len = strlen(pch);
        if (len == 0)
        {
            free(data);
            return WIRE_ERROR;
        }

        if (!isdigit(data[0]))
        {
            free(data);
            return WIRE_ERROR;
        }

        bool hard_addr = false;
        if (len > 1 && pch[len - 1] == '\'')
        {
            pch[len - 1] = '\0';
            hard_addr = true;
        }

        uint32_t x = atoi(pch) | (hard_addr ? 0x80000000U : 0U);
        expanded[index++] = x;
        if (index >= *count)
        {
            free(data);
            return WIRE_ERROR;
        }
        pch = strtok(NULL, "/");
    }

    free(data);
    *count = index;
    return WIRE_SUCCESS;
}

static int collect_and_process_response(const wire_device *device, void **procdata, uint8_t *data, size_t *length, uint16_t *resp_id, size_t *resp_length)
{
	assert(device != NULL);

    memset(data, 0, MSG_OUT_SIZE);
    *resp_id = 0;
    *resp_length = 0;
    *length = MSG_OUT_SIZE;

    int res = hid_device_collect_response(device, data, length, resp_id, resp_length);
    if (res != WIRE_SUCCESS)
        return res;

    if (length == 0)
        return WIRE_NO_RESPONSE;

    res = process_response(device, procdata, data, length, resp_id, resp_length);
    if (res != WIRE_SUCCESS)
        return res;

    return WIRE_SUCCESS;
}

static int decrypt_wire_data(uint8_t *data, uint16_t resp_id, size_t *resp_length, const uint8_t *session_key)
{
    assert(resp_id > 200);
    uint8_t tmp[AES_KEY_SIZE + AES_IV_SIZE];
    memcpy(tmp, session_key, AES_KEY_SIZE);
    memcpy(tmp + AES_KEY_SIZE, data + _msg_header_size, AES_IV_SIZE);

    size_t offset = _msg_header_size + AES_IV_SIZE;
    *resp_length -= AES_IV_SIZE;
    xmr_decrypt_data(data + offset, *resp_length, tmp, WIRE_SESSION_KEY_LENGTH, data + _msg_header_size);
    return WIRE_SUCCESS;
}

static int wire_send(const wire_device *device, const uint8_t *indata, size_t length, const uint8_t *session_key)
{
    uint8_t buffer[MSG_OUT_SIZE];
    uint8_t *data = buffer;

    assert(device != NULL);
    bool allocated_buffer = false;
    size_t buffer_size = sizeof(buffer);
    // ensure we don't fail to a small stack buffer size
    if(length + AES_IV_SIZE > sizeof(buffer))
    {
        buffer_size = length + AES_IV_SIZE;
        data = (uint8_t *) malloc(buffer_size);
        allocated_buffer = true;
    }

    if (session_key == NULL)
        memcpy(data, indata, length);
    else
    {
        uint8_t key[AES_KEY_SIZE + AES_IV_SIZE];
        memcpy(key, session_key, AES_KEY_SIZE);
        uint8_t *iv = key + AES_KEY_SIZE;
        uint16_t msg_id = MSG_ID(indata);
        uint32_t msg_length = MSG_LEN(indata);
        memset(data, 0, buffer_size);
        size_t header_size = pack_header(data, length, msg_id, msg_length + AES_IV_SIZE);
        random_buffer(iv, AES_IV_SIZE);
        memcpy(data + header_size, iv, AES_IV_SIZE);

        xmr_encrypt_data(indata + header_size, msg_length, key, sizeof(key), data + header_size + AES_IV_SIZE);
        length += AES_IV_SIZE;
    }

    int retry = 1;
    bool error = false;
    const int wire_delay = 0;
    while (retry-- >= 0)
    {
        if (hid_device_send(device, data, WIRE_REPORT_BUCKET_SIZE) != WIRE_SUCCESS)
        {
            if (retry > 0)
                continue;
            if(allocated_buffer)
            	free(data);
            return WIRE_ERROR;
        }

        bool do_retry = false;
        if (length > WIRE_REPORT_BUCKET_SIZE)
        {
            length -= WIRE_REPORT_BUCKET_SIZE;
            const int bucket_size = WIRE_REPORT_BUCKET_SIZE - 1;
            int rounds = (length / bucket_size) + ((length % bucket_size) ? 1 : 0);

            uint8_t *p = data + WIRE_REPORT_BUCKET_SIZE;
            for (int i = 0; i < rounds; i++)
            {
                uint8_t bucket[WIRE_REPORT_BUCKET_SIZE];
                memset(bucket, 0, sizeof(bucket));
                bucket[0] = '?';
                memcpy(bucket + 1, p, bucket_size);
                if (hid_device_send(device, bucket, WIRE_REPORT_BUCKET_SIZE) != WIRE_SUCCESS)
                {
                    if (retry > 0)
                    {
                        do_retry = true;
                        break;
                    }
                    if(allocated_buffer) free(data);
                    return WIRE_ERROR;
                }
                p += bucket_size;

            }
        }

        if (do_retry)
            continue;

        break;
    }
    if(allocated_buffer)
    	free(data);
    return WIRE_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// wire functions
#define HID_CLOSE_ON_FUNC_END() //hid_device_close()

#define INIT_WIRE_DATA(_t,_i,_c) do { \
    memset(data, 0, MSG_OUT_SIZE); \
    memcpy(data, _msg_tag, _msg_tag_size); \
    _t _c = _i; \
    uint16_t msg_id = MESSAGE_TYPE(_t); \

#define PACK_WIRE_DATA_AND_SEND(_c) \
    uint32_t msg_length = _c##__get_packed_size(&_c); \
    size_t header_length = pack_header(data, MSG_OUT_SIZE, msg_id, msg_length); \
    _c##__pack(&_c, data + header_length); \
    if (hid_device_send(device, data, WIRE_REPORT_BUCKET_SIZE) != WIRE_SUCCESS) { \
        HID_CLOSE_ON_FUNC_END(); \
        return WIRE_ERROR; } } while(0); \

#define PACK_WIRE_DATA_AND_SEND_ENCRYPTED(_c, _s) \
    uint32_t msg_length = _c##__get_packed_size(&_c); \
    size_t header_length = pack_header(data, MSG_OUT_SIZE, msg_id, msg_length); \
    _c##__pack(&_c, data + header_length); \
    if (wire_send(device, data, msg_length + header_length, _s) != WIRE_SUCCESS) { \
        HID_CLOSE_ON_FUNC_END(); \
        return WIRE_ERROR; } } while(0); \

#define READ_WIRE_DATA_AND_RETURN(_c) do { \
    memset(data, 0, sizeof(data)); \
    size_t length = sizeof(data); \
    uint16_t resp_id = 0; \
    size_t resp_length = 0; \
    int res = collect_and_process_response(device, NULL, data, &length, &resp_id, &resp_length); \
    if (res == WIRE_SUCCESS && _c != NULL) \
        *_c = _c##__unpack(NULL, resp_length, data + _msg_header_size); \
    HID_CLOSE_ON_FUNC_END(); \
    return res; } while (0); \

#define READ_WIRE_DATA_AND_RETURN1() do { \
    memset(data, 0, sizeof(data)); \
    size_t length = sizeof(data); \
    uint16_t resp_id = 0; \
    size_t resp_length = 0; \
    int res = collect_and_process_response(device, NULL, data, &length, &resp_id, &resp_length); \
    HID_CLOSE_ON_FUNC_END(); \
    return res; } while (0); \

#define READ_WIRE_DATA_ENCRYPTED_BEGIN(_r, _s) do { \
    memset(data, 0, sizeof(data)); \
    size_t length = sizeof(data); \
    uint16_t resp_id = 0; \
    size_t resp_length = 0; \
    _r = collect_and_process_response(device, (void **)&_s, data, &length, &resp_id, &resp_length); \

#define READ_WIRE_DATA_ENCRYPTED_END() } while(0); \


int wire_initialize(const wire_device *device, Features **features)
{
    uint8_t data[MSG_OUT_SIZE];

    assert(device != NULL);
    if(device->dev == NULL)
    	return WIRE_ERROR;

    INIT_WIRE_DATA(Initialize, INITIALIZE__INIT, initialize);
    PACK_WIRE_DATA_AND_SEND(initialize);
    READ_WIRE_DATA_AND_RETURN(features);
}

int wire_xmr_get_debug_link_state(DebugLinkState **debug_link_state)
{
    uint8_t data[MSG_OUT_SIZE];

    struct hid_device_info *devs, *cur_dev;

    devs = hid_enumerate(0x0, 0x0);
    cur_dev = devs;
    int cur_interface = -1;
    char *path = NULL;
    while (cur_dev)
    {
        if (cur_dev->vendor_id == idVendor && cur_dev->product_id == idProduct)
        {
            ++cur_interface;
            if (cur_interface == 1)
            {
                size_t len = strlen(cur_dev->path) + 1;
                path = (char *) malloc(len);
                path[len - 1] = '\0';
                strcpy(path, cur_dev->path);
                break;
            }
        }
        cur_dev = cur_dev->next;
    }

    hid_free_enumeration(devs);
    *debug_link_state = NULL;
    if (path == NULL)
        return WIRE_ERROR;

    wire_device device;
    device.dev = hid_open_path(path);
    device.ver = HID_V1;

    free(path);
    path = NULL;

    if (device.dev == NULL)
        return WIRE_ERROR;

    hid_enable_uart_clear_fifo(&device);

    memset(data, 0, sizeof(data));
    memcpy(data, _msg_tag, _msg_tag_size);
    DebugLinkGetState  debug_link_get_state = DEBUG_LINK_GET_STATE__INIT;
    uint16_t msg_id = MESSAGE_TYPE__MessageType_DebugLinkGetState;
    uint32_t msg_length = debug_link_get_state__get_packed_size(&debug_link_get_state);
    size_t header_length = pack_header(data, (128 * 1024), msg_id, msg_length);
    debug_link_get_state__pack(&debug_link_get_state, data + header_length);
    if (hid_device_send(&device, data, 64U) != 0L)
    {
        // close or the next wire calls will use #0 interface
        wire_device_close(&device);
        return -1L;
    }

    memset(data, 0, sizeof(data));
    size_t length = sizeof(data);
    uint16_t resp_id = 0;
    size_t resp_length = 0;
    int res = collect_and_process_response(&device, NULL, data, &length, &resp_id, &resp_length);
    if (res == WIRE_SUCCESS && debug_link_state != NULL)
        *debug_link_state = debug_link_state__unpack(NULL, resp_length, data + _msg_header_size);

    wire_device_close(&device);
    return res;
}

// Note: used by BTC etc only. XMR uses wire_xmr_request_viewkey
int wire_get_address(const wire_device *device, Address **address, const char *path, const char *coin_name, bool show_on_display)
{
    uint8_t data[MSG_OUT_SIZE];

    assert(device != NULL);
    if(device->dev == NULL)
    	return WIRE_ERROR;

    INIT_WIRE_DATA(GetAddress, GET_ADDRESS__INIT, get_address);
    uint32_t expanded[WIRE_MAX_ADDRESS_CHILD_DEPTH];
    size_t count = sizeof(expanded) / sizeof(expanded[0]);
    if (path != NULL && strlen(path))
    {
        if (expand_address_path(path, expanded, &count) != WIRE_SUCCESS)
            return WIRE_ERROR;

        if (count)
        {
            get_address.address_n = expanded;
            get_address.n_address_n = count;
        }
    }

    // NOTE: no multisig
    get_address.has_show_display = true;
    get_address.show_display = show_on_display;
    
    PACK_WIRE_DATA_AND_SEND(get_address);
    READ_WIRE_DATA_AND_RETURN(address);
}

int wire_firmware_update(wire_device *device, const char *file_path)
{
    uint8_t data[512 * 1024];

    assert(device != NULL);
    if(device->dev == NULL)
    	return WIRE_ERROR;

    INIT_WIRE_DATA(FirmwareErase, FIRMWARE_ERASE__INIT, firmware_erase);
    PACK_WIRE_DATA_AND_SEND(firmware_erase);

    memset(data, 0, sizeof(data));
    size_t length = sizeof(data);
    uint16_t resp_id = 0;
    size_t resp_length = 0;
    int res = collect_and_process_response(device, NULL, data, &length, &resp_id, &resp_length);
    if (res != WIRE_SUCCESS)
    {
        wire_device_close(device);
        return res;
    }

    FILE *fp = fopen(file_path, "rb");
    if (fp == NULL)
    {
        wire_device_close(device);
        return WIRE_ERROR;
    }

    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);

    if (size == 0)
    {
        wire_device_close(device);
        return WIRE_ERROR;
    }

    uint8_t *buffer = (uint8_t *)malloc(size);
    if (buffer == NULL)
    {
        wire_device_close(device);
        return WIRE_ERROR;
    }

    fseek(fp, 0, SEEK_SET);
    size_t actual = fread(buffer, 1, size, fp);
    if (actual != size)
    {
        free(buffer);
        wire_device_close(device);
        return WIRE_ERROR;
    }

    memset(data, 0, sizeof(data));
    memcpy(data, _msg_tag, _msg_tag_size); 
    FirmwareUpload firmware_upload = FIRMWARE_UPLOAD__INIT;
    uint16_t msg_id = MESSAGE_TYPE(FirmwareUpload);

    firmware_upload.payload.data = buffer;
    firmware_upload.payload.len = actual;

    uint32_t msg_length = firmware_upload__get_packed_size(&firmware_upload);
    size_t header_length = pack_header(data, sizeof(data), msg_id, msg_length);
    size_t payload_length = msg_length + header_length;
    firmware_upload__pack(&firmware_upload, data + header_length);

    if(wire_send(device, data, payload_length, NULL) != WIRE_SUCCESS)
    {
        wire_device_close(device);
        free(buffer);
        return WIRE_ERROR;
    }

    free(buffer);

    memset(data, 0, sizeof(data));
    length = sizeof(data);
    resp_id = 0;
    resp_length = 0;

    res = collect_and_process_response(device, NULL, data, &length, &resp_id, &resp_length);
    if (res != WIRE_SUCCESS)
    {
        wire_device_close(device);
        return res;
    }

    wire_device_close(device);

    return res;
}

int wire_reset_device(const wire_device *device, const char *label, bool pin_protect, bool passphrase_protect, bool display_random, uint32_t strength)
{
    uint8_t data[MSG_OUT_SIZE];

    assert(device != NULL);
    if(device->dev == NULL)
    	return WIRE_ERROR;

    INIT_WIRE_DATA(ResetDevice, RESET_DEVICE__INIT, reset_device);
    if (label != NULL && strlen(label))
        reset_device.label = (char *) label;

    reset_device.has_pin_protection = true;
    reset_device.pin_protection = pin_protect;
    reset_device.has_passphrase_protection = true;
    reset_device.passphrase_protection = passphrase_protect;
    reset_device.has_display_random = true;
    reset_device.display_random = display_random;
    if (strength == 128 || strength == 192 || strength == 256)
    {
        reset_device.has_strength = true;
        reset_device.strength = strength;
    }
    PACK_WIRE_DATA_AND_SEND(reset_device);
    READ_WIRE_DATA_AND_RETURN1();
}

int wire_wipe_device(const wire_device *device)
{
    uint8_t data[MSG_OUT_SIZE];

    assert(device != NULL);
    if(device->dev == NULL)
    	return WIRE_ERROR;

    INIT_WIRE_DATA(WipeDevice, WIPE_DEVICE__INIT, wipe_device);
    PACK_WIRE_DATA_AND_SEND(wipe_device);
    READ_WIRE_DATA_AND_RETURN1();
}

int wire_recover_device(const wire_device *device, const char *label, size_t word_count, bool pin_protect, bool passphrase_protect, bool verify_words)
{
    uint8_t data[MSG_OUT_SIZE];

    if(word_count != 12 && word_count != 18 && word_count != 24)
        return WIRE_ERROR;

    assert(device != NULL);
    if(device->dev == NULL)
    	return WIRE_ERROR;

    INIT_WIRE_DATA(RecoveryDevice, RECOVERY_DEVICE__INIT, recovery_device);

    recovery_device.has_pin_protection = true;
    recovery_device.pin_protection = pin_protect;
    recovery_device.has_passphrase_protection = true;
    recovery_device.passphrase_protection = passphrase_protect;
    recovery_device.has_enforce_wordlist = true;
    recovery_device.enforce_wordlist = verify_words;
    recovery_device.has_word_count = true;
    recovery_device.word_count = word_count;
    recovery_device.label = (char *) label;
    PACK_WIRE_DATA_AND_SEND(recovery_device);
    READ_WIRE_DATA_AND_RETURN1();
}

int wire_clear_session(const wire_device *device)
{
    uint8_t data[MSG_OUT_SIZE];

    assert(device != NULL);
    if(device->dev == NULL)
    	return WIRE_ERROR;

    INIT_WIRE_DATA(ClearSession, CLEAR_SESSION__INIT, clear_session);
    PACK_WIRE_DATA_AND_SEND(clear_session);
    return WIRE_SUCCESS;
}

int wire_xmr_request_session_key(const wire_device *device, uint8_t *session_key)
{
    uint8_t data[MSG_OUT_SIZE];

    assert(device != NULL);
    if(device->dev == NULL)
    	return WIRE_ERROR;

    xmr_seckey seckey;
    xmr_pubkey pubkey;
    xmr_generate_keys2(&pubkey, &seckey);

    INIT_WIRE_DATA(XmrRequestSessionKey, XMR_REQUEST_SESSION_KEY__INIT, xmr_request_session_key);
    xmr_request_session_key.pubkey.data = pubkey.data;
    xmr_request_session_key.pubkey.len = XMR_KEY_SIZE_BYTES;
    PACK_WIRE_DATA_AND_SEND(xmr_request_session_key);

    memset(data, 0, sizeof(data));
    size_t length = sizeof(data);
    uint16_t resp_id = 0; 
    size_t resp_length = 0;
    uint8_t secret_key[64];
    memcpy(secret_key, seckey.data, XMR_KEY_SIZE_BYTES);
    int res = collect_and_process_response(device, (void **) &secret_key, data, &length, &resp_id, &resp_length);
    if (res == WIRE_SUCCESS)
    {
        memcpy(session_key, secret_key, sizeof(secret_key));
    }

    memset(data, 0, sizeof(data));
    memset(seckey.data, 0, sizeof(seckey.data));
    memset(pubkey.data, 0, sizeof(pubkey.data));

    HID_CLOSE_ON_FUNC_END();
    return res;
}

int wire_xmr_request_viewkey(const wire_device *device, bool display, const char *passphrase, size_t index, const uint8_t *session_key, uint8_t *view_key, uint8_t *pub_spend_key)
{
    uint8_t data[MSG_OUT_SIZE];

    assert(device != NULL);
    if(device->dev == NULL)
    	return WIRE_ERROR;

    INIT_WIRE_DATA(XmrRequestViewKey, XMR_REQUEST_VIEW_KEY__INIT, xmr_request_view_key);
    xmr_request_view_key.account_index = index;
    xmr_request_view_key.passphrase = (char *) passphrase;
    xmr_request_view_key.display_address = display;
    PACK_WIRE_DATA_AND_SEND_ENCRYPTED(xmr_request_view_key, session_key);

    int res = WIRE_ERROR;
    READ_WIRE_DATA_ENCRYPTED_BEGIN(res, session_key);
    if (res == WIRE_SUCCESS)
    {
        XmrRequestViewKeyAck *ack = 
            xmr_request_view_key_ack__unpack(NULL, resp_length, data + _msg_header_size);

        if (ack != NULL)
        {
            assert(ack->viewkey.len == XMR_KEY_SIZE_BYTES);
            assert(ack->spendkey.len == XMR_KEY_SIZE_BYTES);

            uint8_t buffer[2 * XMR_KEY_SIZE_BYTES];
            memcpy(buffer, ack->viewkey.data, XMR_KEY_SIZE_BYTES);
            memcpy(buffer + XMR_KEY_SIZE_BYTES, ack->spendkey.data, XMR_KEY_SIZE_BYTES);

            xmr_hash hash;
            keccak(buffer, sizeof(buffer), hash.data, sizeof(hash.data));
            uint32_t checksum;
            memcpy(&checksum, hash.data, sizeof(checksum));

            if(checksum != ack->checksum)
            {
                res = WIRE_ERROR;
                TLOG("Error: comp: %08x, ack: %08x\n", checksum, ack->checksum);
                TLOG("Error: wire_xmr_request_viewkey checksum failed.\n");
            }
            else
            {
                memcpy(view_key, ack->viewkey.data, XMR_KEY_SIZE_BYTES);
                memcpy(pub_spend_key, ack->spendkey.data, XMR_KEY_SIZE_BYTES);
            }
            free(ack);
            ack = NULL;
        }
    }
    READ_WIRE_DATA_ENCRYPTED_END();
    HID_CLOSE_ON_FUNC_END();

    return res;
}

int wire_xmr_generate_key_image(const wire_device *device, const uint8_t *derivation, const uint8_t *eph_pub_keys, const uint64_t *indices,
    size_t count, const uint8_t *session_key, uint8_t *key_images)
{
    uint8_t data[MSG_OUT_SIZE];

    if (count > WIRE_MAX_KEYIMAGE_GROUP)
    {
        size_t rounds = count / WIRE_MAX_KEYIMAGE_GROUP + (count % WIRE_MAX_KEYIMAGE_GROUP ? 1 : 0);
        size_t total = count;
        for (size_t i = 0; i < rounds; i++)
        {
            size_t offset0 = i * WIRE_MAX_KEYIMAGE_GROUP * XMR_KEY_SIZE_BYTES;
            size_t offset1 = i * WIRE_MAX_KEYIMAGE_GROUP;
            size_t actual_count = WIRE_MAX_KEYIMAGE_GROUP;
            if (i == rounds - 1 && count % WIRE_MAX_KEYIMAGE_GROUP)
                actual_count = count % WIRE_MAX_KEYIMAGE_GROUP;

            int res = wire_xmr_generate_key_image(device, derivation, eph_pub_keys + offset0, &indices[offset1],
                actual_count, session_key, key_images + offset0);

            if (res != WIRE_SUCCESS)
                return WIRE_ERROR;
        }

        return WIRE_SUCCESS;
    }

    assert(device != NULL);
    if(device->dev == NULL)
    	return WIRE_ERROR;

    uint8_t tmp_pub_keys[XMR_KEY_SIZE_BYTES * WIRE_MAX_KEYIMAGE_GROUP];
    uint8_t tmp_derivation[XMR_KEY_SIZE_BYTES * WIRE_MAX_KEYIMAGE_GROUP];
    uint8_t tmp_indices[WIRE_MAX_KEYIMAGE_GROUP * sizeof(uint64_t)];

    const xmr_pubkey *pubkeys = (xmr_pubkey *)eph_pub_keys;
    xmr_pubkey *hashed_pubkeys = (xmr_pubkey *)tmp_pub_keys;
    ec_scalar *scalars = (ec_scalar *)tmp_derivation;
    for (size_t i = 0; i < count; i++)
    {
        keccak(pubkeys[i].data, XMR_KEY_SIZE_BYTES, hashed_pubkeys[i].data, XMR_HASH_SIZE);
        xmr_derivation_to_scalar((const xmr_derivation *) derivation, indices[i], &scalars[i]);
    }

    INIT_WIRE_DATA(XmrGenerateKeyImage, XMR_GENERATE_KEY_IMAGE__INIT, xmr_generate_key_image);

    xmr_generate_key_image.derivation.data = tmp_derivation;
    xmr_generate_key_image.eph_pubkey.data = tmp_pub_keys;
    xmr_generate_key_image.indices.data = tmp_indices;

    xmr_generate_key_image.derivation.len = count * XMR_KEY_SIZE_BYTES;
    xmr_generate_key_image.eph_pubkey.len = count * XMR_KEY_SIZE_BYTES;
    xmr_generate_key_image.indices.len = 0;
    xmr_generate_key_image.count = count;

    PACK_WIRE_DATA_AND_SEND_ENCRYPTED(xmr_generate_key_image, session_key);

    int res = WIRE_ERROR;
    READ_WIRE_DATA_ENCRYPTED_BEGIN(res, session_key);
    if (res == WIRE_SUCCESS)
    {
        XmrGenerateKeyImageAck *ack =
            xmr_generate_key_image_ack__unpack(NULL, resp_length, data + _msg_header_size);

        if (ack != NULL)
        {
            assert(ack->key_image.len <= 11264);
            xmr_hash hash;
            keccak(ack->key_image.data, ack->key_image.len, hash.data, sizeof(hash.data));
            uint32_t checksum;
            memcpy(&checksum, hash.data, sizeof(checksum));
            if(checksum != ack->checksum)
            {
                res = WIRE_ERROR;
                TLOG("Error: comp: %08x, ack: %08x\n", checksum, ack->checksum);
                TLOG("Error: wire_xmr_generate_key_image checksum failed.\n");
            }
            else
            {
                memcpy(key_images, ack->key_image.data, ack->key_image.len);
            }

            free(ack);
            ack = NULL;
        }
    }
    READ_WIRE_DATA_ENCRYPTED_END();

    HID_CLOSE_ON_FUNC_END();
    return res;
}

int wire_xmr_generate_tx_init(const wire_device *device, uint64_t version, uint64_t unlock_time, uint32_t mixin, uint32_t vin_count, uint32_t vout_count,
    const uint8_t *addresses, size_t addresses_count, const uint8_t *session_key, uint8_t *tx_seckey, uint64_t *tx_construction_id)
{
    uint8_t data[MSG_OUT_SIZE];

    assert(device != NULL);
    if(device->dev == NULL)
    	return WIRE_ERROR;

    assert(addresses_count <= XMR_MAX_OUT_ADDRESSES);
    assert(mixin <= XMR_MAX_MIXIN_LEVEL);
    assert(vin_count <= XMR_MAX_VIN_COUNT);
    assert(vout_count <= XMR_MAX_VOUT_COUNT); 

    INIT_WIRE_DATA(XmrGenerateTxInit, XMR_GENERATE_TX_INIT__INIT, xmr_generate_tx_init);
    xmr_generate_tx_init.version = version;
    xmr_generate_tx_init.unlock_time = unlock_time;
    xmr_generate_tx_init.mixin = mixin;
    xmr_generate_tx_init.vin_count = vin_count;
    xmr_generate_tx_init.vout_count = vout_count;
    xmr_generate_tx_init.tx_fee = XMR_TX_FEE_PER_KB;
    
    if(addresses_count > 0)
    {
        xmr_generate_tx_init.has_dest_addresses = true;
        xmr_generate_tx_init.dest_addresses.data = (uint8_t *)addresses;
        xmr_generate_tx_init.dest_addresses.len = addresses_count * sizeof(xmr_address);
    }
    else
    {
        xmr_generate_tx_init.has_dest_addresses = false;
        xmr_generate_tx_init.dest_addresses.data = NULL;
        xmr_generate_tx_init.dest_addresses.len = 0;
    }

    PACK_WIRE_DATA_AND_SEND_ENCRYPTED(xmr_generate_tx_init, session_key);

    int res = WIRE_ERROR;
    READ_WIRE_DATA_ENCRYPTED_BEGIN(res, session_key);
    if (res == WIRE_SUCCESS)
    {
        XmrGenerateTxInitAck *ack =
            xmr_generate_tx_init_ack__unpack(NULL, resp_length, data + _msg_header_size);

        if (ack != NULL)
        {
            *tx_construction_id = ack->txid;
            if(tx_seckey != NULL)
            {
                assert(ack->tx_seckey.len == XMR_KEY_SIZE_BYTES);
                memcpy(tx_seckey, ack->tx_seckey.data, XMR_KEY_SIZE_BYTES);
            }
            free(ack);
            ack = NULL;
        }
    }
    READ_WIRE_DATA_ENCRYPTED_END();

    HID_CLOSE_ON_FUNC_END();
    return res;
}

int wire_xmr_generate_tx_vin(const wire_device *device, const uint64_t *amounts, const uint8_t *derivations, const uint8_t *eph_pubkeys, const uint64_t *out_indices,
    size_t vin_count, const uint64_t *offsets, size_t offset_count, uint64_t tx_construction_id, const uint8_t *session_key, uint8_t *key_images)
{
    uint8_t data[MSG_OUT_SIZE];

    assert(vin_count <= XMR_MAX_VIN_COUNT);

    assert(device != NULL);
    if(device->dev == NULL)
    	return WIRE_ERROR;

    if (vin_count > WIRE_MAX_VIN_GROUP)
    {
        size_t rounds = vin_count / WIRE_MAX_VIN_GROUP + (vin_count % WIRE_MAX_VIN_GROUP ? 1 : 0);
        size_t total = vin_count;
        for (size_t i = 0; i < rounds; i++)
        {
            size_t offset0 = i * WIRE_MAX_VIN_GROUP * XMR_KEY_SIZE_BYTES;
            size_t offset1 = i * WIRE_MAX_VIN_GROUP;
            size_t actual_count = WIRE_MAX_VIN_GROUP;
            if (i == rounds - 1 && vin_count % WIRE_MAX_VIN_GROUP)
                actual_count = vin_count % WIRE_MAX_VIN_GROUP;

            int res = wire_xmr_generate_tx_vin(device, &amounts[offset1], derivations + offset0, eph_pubkeys + offset0,
                &out_indices[offset1], actual_count, &offsets[offset1 * offset_count], offset_count,
                tx_construction_id, session_key, key_images + offset0);

            if (res != WIRE_SUCCESS)
                return WIRE_ERROR;
        }

        return WIRE_SUCCESS;
    }

    xmr_hash hash_eph_pubkeys[WIRE_MAX_VIN_GROUP];
    memset(hash_eph_pubkeys, 0, sizeof(hash_eph_pubkeys));
    ec_scalar scalars[WIRE_MAX_VIN_GROUP];
    memset(scalars, 0, sizeof(scalars));

    const xmr_pubkey *pubkeys = (xmr_pubkey *)eph_pubkeys;
    
    for (size_t i = 0; i < vin_count; i++)
    {
        keccak(pubkeys[i].data, XMR_KEY_SIZE_BYTES, hash_eph_pubkeys[i].data, XMR_HASH_SIZE);
        xmr_derivation_to_scalar(&((const xmr_derivation *) derivations)[i], out_indices[i], &scalars[i]);
    }

    XmrInputType *vin[WIRE_MAX_VIN_GROUP];
    XmrInputType vin_data[WIRE_MAX_VIN_GROUP];
    for (size_t i = 0; i < vin_count; i++)
    {
        vin[i] = &vin_data[i];
        xmr_input_type__init(vin[i]);
        vin[i]->amount = amounts[i];
        size_t offset = i * XMR_KEY_SIZE_BYTES;

        vin[i]->derivation.data = scalars[i].data;
        vin[i]->derivation.len = XMR_KEY_SIZE_BYTES;
        vin[i]->eph_pubkey.data = hash_eph_pubkeys[i].data;
        vin[i]->eph_pubkey.len = XMR_KEY_SIZE_BYTES;
        vin[i]->out_tx_index = out_indices[i];
        vin[i]->offsets.data = (uint8_t *) &offsets[i * offset_count];
        vin[i]->offsets.len = offset_count * sizeof(uint64_t);
    }


    INIT_WIRE_DATA(XmrGenerateTxVin, XMR_GENERATE_TX_VIN__INIT, xmr_generate_tx_vin);
    xmr_generate_tx_vin.txid = tx_construction_id;
    xmr_generate_tx_vin.n_ins = vin_count;
    xmr_generate_tx_vin.ins = vin;
    PACK_WIRE_DATA_AND_SEND_ENCRYPTED(xmr_generate_tx_vin, session_key);

    int res = WIRE_ERROR;
    READ_WIRE_DATA_ENCRYPTED_BEGIN(res, session_key);
    if (res == WIRE_SUCCESS)
    {
        XmrGenerateTxVinAck *ack =
            xmr_generate_tx_vin_ack__unpack(NULL, resp_length, data + _msg_header_size);

        if (ack != NULL)
        {
            memcpy(key_images, ack->key_images.data, ack->key_images.len);
            free(ack);
            ack = NULL;
        }
    }
    READ_WIRE_DATA_ENCRYPTED_END();

    HID_CLOSE_ON_FUNC_END();
    return res;
}

int wire_xmr_generate_tx_vout(const wire_device *device, const uint64_t *amounts, const int32_t *addr_indices,
        size_t vout_count, uint64_t tx_construction_id, const uint8_t *session_key, uint8_t *pubkeys)
{
    uint8_t data[MSG_OUT_SIZE];

    assert(vout_count <= XMR_MAX_VOUT_COUNT);

    assert(device != NULL);
    if(device->dev == NULL)
    	return WIRE_ERROR;

    if (vout_count > WIRE_MAX_VOUT_GROUP)
    {
        size_t rounds = vout_count / WIRE_MAX_VOUT_GROUP + (vout_count % WIRE_MAX_VOUT_GROUP ? 1 : 0);
        size_t total = vout_count;
        for (size_t i = 0; i < rounds; i++)
        {
            size_t offset0 = i * WIRE_MAX_VOUT_GROUP;
            size_t actual_count = WIRE_MAX_VOUT_GROUP;
            if (i == rounds - 1 && vout_count % WIRE_MAX_VOUT_GROUP)
                actual_count = vout_count % WIRE_MAX_VOUT_GROUP;

            int res = wire_xmr_generate_tx_vout(device, &amounts[offset0], &addr_indices[offset0], actual_count,
                    tx_construction_id, session_key, pubkeys + (offset0 * XMR_KEY_SIZE_BYTES));

            if (res != WIRE_SUCCESS)
                return WIRE_ERROR;
        }

        return WIRE_SUCCESS;
    }

    XmrOutputType *vout[XMR_MAX_VOUT_COUNT];
    XmrOutputType vout_data[XMR_MAX_VOUT_COUNT];
    for (size_t i = 0; i < vout_count; i++)
    {
        vout[i] = &vout_data[i];
        xmr_output_type__init(vout[i]);
        vout[i]->amount = amounts[i];
        vout[i]->address_index = addr_indices[i];
    }

    INIT_WIRE_DATA(XmrGenerateTxVout, XMR_GENERATE_TX_VOUT__INIT, xmr_generate_tx_vout);
    xmr_generate_tx_vout.txid = tx_construction_id;
    xmr_generate_tx_vout.n_outs = vout_count;
    xmr_generate_tx_vout.outs = vout;
    PACK_WIRE_DATA_AND_SEND_ENCRYPTED(xmr_generate_tx_vout, session_key);
    int res = WIRE_ERROR;
    READ_WIRE_DATA_ENCRYPTED_BEGIN(res, session_key);
    if (res == WIRE_SUCCESS)
    {
        XmrGenerateTxVoutAck *ack =
            xmr_generate_tx_vout_ack__unpack(NULL, resp_length, data + _msg_header_size);

        if (ack != NULL)
        {
            memcpy(pubkeys, ack->pubkeys.data, ack->pubkeys.len);
            free(ack);
            ack = NULL;
        }
    }
    READ_WIRE_DATA_ENCRYPTED_END();

    HID_CLOSE_ON_FUNC_END();
    return res;
}

int wire_xmr_generate_tx_extra(const wire_device *device, const uint8_t *payment_id, size_t payment_id_size, uint8_t *tx_prefix_hash,
    uint8_t *extra_bytes, size_t *extra_bytes_length, uint64_t tx_construction_id, const uint8_t *session_key)
{
    uint8_t data[MSG_OUT_SIZE];

    assert(payment_id_size == 32 || payment_id_size == 8);

    assert(device != NULL);
    if(device->dev == NULL)
    	return WIRE_ERROR;

    INIT_WIRE_DATA(XmrGenerateTxExtra, XMR_GENERATE_TX_EXTRA__INIT, xmr_generate_tx_extra);
    xmr_generate_tx_extra.txid = tx_construction_id;

    if (payment_id != NULL)
    {
        xmr_generate_tx_extra.payment_id.data = (uint8_t *)payment_id;
        xmr_generate_tx_extra.has_payment_id = true;
        xmr_generate_tx_extra.has_payment_id_ver = true;

        xmr_generate_tx_extra.payment_id.data = (uint8_t *) payment_id;
        xmr_generate_tx_extra.payment_id.len = payment_id_size;
        xmr_generate_tx_extra.payment_id_ver = payment_id_size == 8 ? 1 : 0;
    }
    else
    {
        xmr_generate_tx_extra.has_payment_id = false;
        xmr_generate_tx_extra.has_payment_id_ver = false;

        xmr_generate_tx_extra.payment_id.data = NULL;
        xmr_generate_tx_extra.payment_id.len = 0;
        xmr_generate_tx_extra.payment_id_ver = 0;
    }

    PACK_WIRE_DATA_AND_SEND_ENCRYPTED(xmr_generate_tx_extra, session_key);

    int res = WIRE_ERROR;
    READ_WIRE_DATA_ENCRYPTED_BEGIN(res, session_key);
    if (res == WIRE_SUCCESS)
    {
        XmrGenerateTxExtraAck *ack =
            xmr_generate_tx_extra_ack__unpack(NULL, resp_length, data + _msg_header_size);

        if (ack != NULL)
        {
            if (ack->prefix_hash.len > 0)
            {
                assert(ack->prefix_hash.len == XMR_KEY_SIZE_BYTES);
                memcpy(tx_prefix_hash, ack->prefix_hash.data, XMR_KEY_SIZE_BYTES);
                assert(ack->extra.len <= 68);
                assert(ack->extra.len >= 33);
                memcpy(extra_bytes, ack->extra.data, ack->extra.len);
                *extra_bytes_length = ack->extra.len;
            }
            free(ack);
            ack = NULL;
        }
    }
    READ_WIRE_DATA_ENCRYPTED_END();
    HID_CLOSE_ON_FUNC_END();
    return res;
}

int wire_xmr_generate_tx_signature(const wire_device *device, const uint8_t *streams, size_t length_per_stream, const uint8_t *derivations,
    const uint8_t *sums, const uint64_t *out_indices, const uint8_t *pubkeys, size_t sig_count,
    uint64_t tx_construction_id, const uint8_t *session_key, uint8_t *signatures)
{
    uint8_t data[MSG_OUT_SIZE];

    assert(length_per_stream != 0);
    assert(sig_count != 0);

    assert(device != NULL);
    if(device->dev == NULL)
    	return WIRE_ERROR;

    if(length_per_stream > XMR_MAX_STREAM_LENGTH)
        return WIRE_ERROR;

    if (sig_count > WIRE_MAX_SIG_GROUP)
    {
        size_t rounds = sig_count / WIRE_MAX_SIG_GROUP + (sig_count % WIRE_MAX_SIG_GROUP ? 1 : 0);
        size_t total = sig_count;
        for (size_t i = 0; i < rounds; i++)
        {
            size_t stream_offset = i * WIRE_MAX_SIG_GROUP * length_per_stream;
            size_t offset0 = i * WIRE_MAX_SIG_GROUP * XMR_KEY_SIZE_BYTES;
            size_t offset1 = i * WIRE_MAX_SIG_GROUP;
            size_t actual_count = WIRE_MAX_SIG_GROUP;
            if (i == rounds - 1 && sig_count % WIRE_MAX_SIG_GROUP)
                actual_count = sig_count % WIRE_MAX_SIG_GROUP;

            int res = wire_xmr_generate_tx_signature(device, streams + stream_offset, length_per_stream, derivations + offset0,
                    sums + offset0, &out_indices[offset1], pubkeys + offset0, actual_count,
                    tx_construction_id, session_key, signatures + (i * WIRE_MAX_SIG_GROUP * sizeof(xmr_signature)));

            if (res != WIRE_SUCCESS)
                return WIRE_ERROR;
        }

        return WIRE_SUCCESS;
    }

    if (length_per_stream > WIRE_MAX_STREAM_LENGTH)
        return WIRE_STREAM_TOO_LONG;

    ec_scalar scalars[WIRE_MAX_SIG_GROUP];
    memset(scalars, 0, sizeof(scalars));
    for (size_t i = 0; i < sig_count; i++)
    {
        xmr_derivation_to_scalar(&((const xmr_derivation *) derivations)[i], out_indices[i], &scalars[i]);
    }

    xmr_pubkey *pubs = (xmr_pubkey *)pubkeys;
    ec_scalar *hashsums = (ec_scalar *) sums;

    uint8_t tmp_stream[WIRE_MAX_SIG_GROUP * XMR_MAX_STREAM_LENGTH];
    memcpy(tmp_stream, streams, sig_count * length_per_stream);

    XmrSignatureType *sig[WIRE_MAX_SIG_GROUP];
    XmrSignatureType sig_data[WIRE_MAX_SIG_GROUP];
    for (size_t i = 0; i < sig_count; i++)
    {
        sig[i] = &sig_data[i];
        xmr_signature_type__init(sig[i]);
        sig[i]->derivation.data = scalars[i].data;
        sig[i]->derivation.len = XMR_KEY_SIZE_BYTES;
        sig[i]->pubkey.data = pubs[i].data;
        sig[i]->pubkey.len = XMR_KEY_SIZE_BYTES;
        sig[i]->sum.data = hashsums[i].data;
        sig[i]->sum.len = XMR_KEY_SIZE_BYTES;
        sig[i]->stream.data = (tmp_stream + (i * length_per_stream));
        sig[i]->stream.len = length_per_stream;
        sig[i]->has_stream = true;
    }

    INIT_WIRE_DATA(XmrGenerateSignature, XMR_GENERATE_SIGNATURE__INIT, xmr_generate_signature);

    xmr_generate_signature.txid = tx_construction_id;
    xmr_generate_signature.n_data = sig_count;
    xmr_generate_signature.data = sig;
    xmr_generate_signature.version = 0;

    PACK_WIRE_DATA_AND_SEND_ENCRYPTED(xmr_generate_signature, session_key);

    int res = WIRE_ERROR;
    READ_WIRE_DATA_ENCRYPTED_BEGIN(res, session_key);
    if (res == WIRE_SUCCESS)
    {
        XmrGenerateSignatureAck *ack =
            xmr_generate_signature_ack__unpack(NULL, resp_length, data + _msg_header_size);

        if (ack != NULL)
        {
            xmr_signature *outsig = (xmr_signature *) signatures;
            assert(ack->c.len < WIRE_MAX_SIG_GROUP * sizeof(ec_scalar));
            assert(ack->r.len < WIRE_MAX_SIG_GROUP * sizeof(ec_scalar));
            const ec_scalar *c = (ec_scalar *) ack->c.data;
            const ec_scalar *r = (ec_scalar *) ack->r.data;
            for(int i = 0; i < sig_count; i++)
            {
                memcpy(outsig[i].c.data, c[i].data, sizeof(outsig[i].c.data));
                memcpy(outsig[i].r.data, r[i].data, sizeof(outsig[i].r.data));
            }

            xmr_hash hash;
            keccak(signatures, sig_count * sizeof(xmr_signature), hash.data, sizeof(hash.data));
            uint32_t checksum;
            memcpy(&checksum, hash.data, sizeof(checksum));

            if(checksum != ack->checksum)
            {
                memset(signatures, 0, sig_count * sizeof(xmr_signature));
                res = WIRE_ERROR;
                TLOG("Error: comp: %08x, ack: %08x\n", checksum, ack->checksum);
                TLOG("Error: wire_xmr_generate_tx_signature checksum failed.\n");
            }

            free(ack);
            ack = NULL;
        }
    }
    READ_WIRE_DATA_ENCRYPTED_END();

    HID_CLOSE_ON_FUNC_END();
    return res;
}

int wire_ping(const wire_device *device, const char *message, bool pin_protect, bool passphrase_protect, bool button_protect)
{
    uint8_t data[MSG_OUT_SIZE];

    assert(device != NULL);
    if(device->dev == NULL)
    	return WIRE_ERROR;

    INIT_WIRE_DATA(Ping, PING__INIT, ping);
    ping.has_button_protection = true;
    ping.button_protection = button_protect;
    ping.has_passphrase_protection = true;
    ping.passphrase_protection = passphrase_protect;
    ping.has_pin_protection = true;
    ping.pin_protection = pin_protect;
    PACK_WIRE_DATA_AND_SEND(ping);
    READ_WIRE_DATA_AND_RETURN1();
}

wire_pin_function_t wire_set_pin_function(wire_pin_function_t func)
{
	wire_pin_function_t oldfunc = _pin_function;
    _pin_function = func;
    return oldfunc;
}

wire_passphrase_function_t wire_set_passphrase_function(wire_passphrase_function_t func)
{
	wire_passphrase_function_t oldfunc = _passphrase_function;
    _passphrase_function = func;
    return oldfunc;
}

wire_display_failure_function_t wire_set_failure_function(wire_display_failure_function_t func)
{
	wire_display_failure_function_t oldfunc = _failure_function;
    _failure_function = func;
    return oldfunc;
}

wire_display_success_function_t wire_set_success_function(wire_display_success_function_t func)
{
	wire_display_success_function_t oldfunc = _success_function;
    _success_function = func;
    return oldfunc;
}

wire_display_fingerprint_function_t wire_set_display_fingerprint_function(wire_display_fingerprint_function_t func)
{
	wire_display_fingerprint_function_t oldfunc = _display_fingerprint_function;
    _display_fingerprint_function = func;
    return oldfunc;
}

wire_recovery_word_function_t wire_set_recovery_word_function(wire_recovery_word_function_t func)
{
	wire_recovery_word_function_t oldfunc = _recovery_word_function;
    _recovery_word_function = func;
    return oldfunc;
}

////////////////////////////////////////////////////////////////////////////////
// process functions (messages, prompts etc)
DEFINE_PROCESS_FUNCTION(Success)
{
    Success *success = success__unpack(NULL, *resp_length, data + _msg_header_size);
    if (success == NULL)
        return WIRE_SUCCESS; // success regardless.

    if (success->message && strlen(success->message))
        _success_function(success->message);

    free(success);
    return WIRE_SUCCESS;
}

DEFINE_PROCESS_FUNCTION(Failure)
{
    Failure *failure = failure__unpack(NULL, *resp_length, data + _msg_header_size);
    if (failure == NULL)
        return WIRE_ERROR; // error regardless.

    if (failure->message && strlen(failure->message))
        _failure_function(failure->message);

    free(failure);
    return WIRE_ERROR;
}

DEFINE_PROCESS_FUNCTION(Entropy)
{
    return WIRE_SUCCESS;
}

DEFINE_PROCESS_FUNCTION(PublicKey)
{
    return WIRE_SUCCESS;
}

DEFINE_PROCESS_FUNCTION(Features)
{
    return WIRE_SUCCESS;
}

DEFINE_PROCESS_FUNCTION(PinMatrixRequest)
{
    PinMatrixRequest *pin_matrix_request = pin_matrix_request__unpack(NULL, *resp_length, data + _msg_header_size);

    if (pin_matrix_request == NULL)
        return WIRE_ERROR;

    PinMatrixRequestType type = PIN_MATRIX_REQUEST_TYPE__PinMatrixRequestType_Current;
    if (pin_matrix_request->has_type)
        type = pin_matrix_request->type;

    free(pin_matrix_request);
    
    char pin[256];
    memset(pin, 0, sizeof(pin));
    if (_pin_function(type, pin, sizeof(pin)) != WIRE_SUCCESS)
        return WIRE_ERROR;

    INIT_WIRE_DATA(PinMatrixAck, PIN_MATRIX_ACK__INIT, pin_matrix_ack);
    pin_matrix_ack.pin = pin;
    PACK_WIRE_DATA_AND_SEND(pin_matrix_ack);
    return collect_and_process_response(device, procdata, data, length, resp_id, resp_length);
}

DEFINE_PROCESS_FUNCTION(CipheredKeyValue)
{

    return WIRE_SUCCESS;
}

DEFINE_PROCESS_FUNCTION(ButtonRequest)
{
    INIT_WIRE_DATA(ButtonAck, BUTTON_ACK__INIT, button_ack);
    PACK_WIRE_DATA_AND_SEND(button_ack);
    return collect_and_process_response(device, procdata, data, length, resp_id, resp_length);
}

DEFINE_PROCESS_FUNCTION(Address)
{
    return WIRE_SUCCESS;
}

DEFINE_PROCESS_FUNCTION(EntropyRequest)
{
    INIT_WIRE_DATA(EntropyAck, ENTROPY_ACK__INIT, entropy_ack);
    uint8_t random[32];
    random_buffer(random, sizeof(random));
    entropy_ack.has_entropy = true;
    entropy_ack.entropy.len = sizeof(random);
    entropy_ack.entropy.data = random;
    PACK_WIRE_DATA_AND_SEND(entropy_ack);
    return collect_and_process_response(device, procdata, data, length, resp_id, resp_length);
}

DEFINE_PROCESS_FUNCTION(MessageSignature)
{
    return WIRE_SUCCESS;
}

DEFINE_PROCESS_FUNCTION(SignedIdentity)
{
    return WIRE_SUCCESS;
}

DEFINE_PROCESS_FUNCTION(EncryptedMessage)
{
    return WIRE_SUCCESS;
}

DEFINE_PROCESS_FUNCTION(DecryptedMessage)
{
    return WIRE_SUCCESS;
}

DEFINE_PROCESS_FUNCTION(PassphraseRequest)
{
    char pass[256];
    memset(pass, 0, sizeof(pass));
    if (_passphrase_function(pass, sizeof(pass)) != WIRE_SUCCESS)
        return WIRE_ERROR;

    INIT_WIRE_DATA(PassphraseAck, PASSPHRASE_ACK__INIT, passphrase_ack);
    passphrase_ack.passphrase = pass;
    PACK_WIRE_DATA_AND_SEND(passphrase_ack);
    return collect_and_process_response(device, procdata, data, length, resp_id, resp_length);
}

DEFINE_PROCESS_FUNCTION(WordRequest)
{
    char word[256];
    memset(word, 0, sizeof(word));
    if (_recovery_word_function(word, sizeof(word)) != WIRE_SUCCESS)
        return WIRE_ERROR;

    INIT_WIRE_DATA(WordAck, WORD_ACK__INIT, word_ack);
    word_ack.word = word;
    PACK_WIRE_DATA_AND_SEND(word_ack);
    return collect_and_process_response(device, procdata, data, length, resp_id, resp_length);
}

DEFINE_PROCESS_FUNCTION(XmrRequestSessionKeyAck)
{
    XmrRequestSessionKeyAck *xmr_request_session_key_ack =
        xmr_request_session_key_ack__unpack(NULL, *resp_length, data + _msg_header_size);

    if (xmr_request_session_key_ack == NULL)
        return WIRE_ERROR;

    uint8_t (*seckey)[64] = (uint8_t (*)[64]) procdata;

    uint8_t shared_secret[XMR_KEY_SIZE_BYTES * 2];
    uint8_t fingerprint[XMR_KEY_SIZE_BYTES];

    ed25519_key_exchange(shared_secret, xmr_request_session_key_ack->pubkey.data, *seckey);
    keccak(shared_secret, XMR_KEY_SIZE_BYTES, shared_secret, sizeof(shared_secret));
    keccak(shared_secret, sizeof(shared_secret), fingerprint, sizeof(fingerprint));

    free(xmr_request_session_key_ack);
    memcpy(*seckey, shared_secret, sizeof(shared_secret));
    char str[256];
    data_to_hex(fingerprint, XMR_FINGERPRINT_LENGTH, str);
    _display_fingerprint_function(str);
    // add some wait time for button
    sleep_ms(250);
    return collect_and_process_response(device, procdata, data, length, resp_id, resp_length);
}

#define DECRYPT_WIRE_DATA_AND_RETURN() do {\
    uint8_t **session_key = (uint8_t **)procdata; \
    return decrypt_wire_data(data, *resp_id, resp_length, *session_key); } while(0); \

DEFINE_PROCESS_FUNCTION(XmrRequestViewKeyAck)
{
    DECRYPT_WIRE_DATA_AND_RETURN();
}

DEFINE_PROCESS_FUNCTION(XmrGenerateKeyImageAck)
{
    DECRYPT_WIRE_DATA_AND_RETURN();
}

DEFINE_PROCESS_FUNCTION(XmrGenerateSignatureAck)
{
    DECRYPT_WIRE_DATA_AND_RETURN();
}

DEFINE_PROCESS_FUNCTION(XmrGenerateTxInitAck)
{
    DECRYPT_WIRE_DATA_AND_RETURN();
}

DEFINE_PROCESS_FUNCTION(XmrGenerateTxExtraAck)
{
    DECRYPT_WIRE_DATA_AND_RETURN();
}

DEFINE_PROCESS_FUNCTION(XmrGenerateTxVinAck)
{
    DECRYPT_WIRE_DATA_AND_RETURN();
}

DEFINE_PROCESS_FUNCTION(XmrGenerateTxVoutAck)
{
    DECRYPT_WIRE_DATA_AND_RETURN();
}
