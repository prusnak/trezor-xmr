#if !defined(__KEY_EXCHANGE_H__)
#define __KEY_EXCHANGE_H__

#ifdef __cplusplus
extern "C" {
#endif

void ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key);

#ifdef __cplusplus
}
#endif

#endif
