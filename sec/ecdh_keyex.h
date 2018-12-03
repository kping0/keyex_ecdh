#ifndef ECDH_KEYEX_H
#define ECDH_KEYEX_H

#include <stdio.h>
#include <stdlib.h>
#include <bsd/stdlib.h>
#include "ecdh_base.h"
#include "base64.h"

typedef unsigned char byte;

typedef struct{
	/* own public/private keys */
	dhkey idk1s; /* identity key */
	dhkey ek1s; /* temp key */
	byte sig_ek1s[64]; /* temp key signature (signed by idk1s) */

	/* foreign public keys */
	dhkey idk1o; /* identity key */
	dhkey ek1o; /* temp key */

	/* salts */
	byte salt1s[64]; /* own generated salt */
	byte sig_salt1s[64]; /* temp salt sig */
	byte salt1o[64]; /* foreign generated salt */

	int err;
	int allow_import_idk;
	int can_compute_secret;
	short chkval; /* set to 0xFF if keyex_init has been run */

}keyex_ctx;

void keyex_calcsecret(dhkey* idk1o, dhkey* ek1o, dhkey* idk1s, dhkey* ek1s, byte* salt, byte* secret);

void keyex_init(dhkey* idk1s, keyex_ctx* kctx);

void keyex_set_fidk(dhkey* idk1o, keyex_ctx* kctx);

byte* keyex_infopacket(keyex_ctx* kctx);

void keyex_process(byte* b64buf, keyex_ctx* kctx);

void keyex_compute(byte* sk_out, keyex_ctx* kctx);

#endif
