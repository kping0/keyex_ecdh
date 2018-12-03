#ifndef C25519_H
#define C25519_H

#include <stddef.h>

#if defined(_WIN32)
    #if defined(C25519_BUILD_DLL)
        #define C25519_DECLSPEC __declspec(dllexport)
    #elif defined(C25519_DLL)
        #define C25519_DECLSPEC __declspec(dllimport)
    #else
        #define C25519_DECLSPEC
    #endif
#else
    #define C25519_DECLSPEC
#endif


#ifdef __cplusplus
extern "C" {
#endif

#ifndef C25519_NO_SEED
int C25519_DECLSPEC curve25519_create_seed(unsigned char *seed);
#endif

void C25519_DECLSPEC curve25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed);
void C25519_DECLSPEC curve25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key);
int C25519_DECLSPEC curve25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key);
void C25519_DECLSPEC curve25519_add_scalar(unsigned char *public_key, unsigned char *private_key, const unsigned char *scalar);
void C25519_DECLSPEC curve25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key);


#ifdef __cplusplus
}
#endif

#endif
