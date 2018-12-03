#ifndef CRYPTO_EXCHANGE_H
#define CRYPTO_EXCHANGE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "sha512.h"
#include "curve25519.h"

typedef unsigned char byte;

typedef struct {
	byte name[32];
	byte pub[32];
	byte priv[64];	
}dhkey;

#define DHKEYCHECK(x) assert(x && x->pub && x->priv)
#define FOREIGN_DHKEYCHECK(x) assert(x && x->pub)

void hexdump(byte* mem, size_t len);

void ECDH(byte* public, byte* private, byte* secret_out); /* get 32B key out of DH */

int ECDH_hsalt(dhkey* foreignkey, dhkey* ownkey, byte* salt, byte* hash_out); /* foreignkey, ownkey, 64B salt, 64B out buffer for key */

int ECDH_newkey(const char* name, dhkey* key); /* requires: name(max 31), key out struct */

#ifdef DEBUG
void ECDH_dumpkey(dhkey* key);
#endif

int ECDH_verify(dhkey* idk1o, byte* sig, byte* buf, size_t bufsz);

int ECDH_sign(dhkey* idk1s, byte* sig, byte* buf, size_t bufsz);

#endif
