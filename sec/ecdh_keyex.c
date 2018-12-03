#include "ecdh_keyex.h"

static void xor(byte* s1, byte* s2, size_t len, byte* out) /* xor s1,s2 for len > out(must hold len)*/
{
	for(size_t i = 0; i < len; i++)
	{
		out[i] = s1[i] ^ s2[i];	
	}
}

void keyex_calcsecret(dhkey* idk1o, dhkey* ek1o, dhkey* idk1s, dhkey* ek1s, byte* salt, byte* secret)
{
	/*
	 * To use this function:
	 * first parameter: idk1o => other party identity key (permanent)
	 * second parameter: ek1o => other party ephemeral key (temporary)
	 * third parameter: idk1s => your identity key (permanent)
	 * fourth parameter: ek1s => your ephemeral key (temporary)
	 * fifth parameter: salt => agreed salt with other party
	 * sixth parameter: secret => out buffer for shared secret (must hold min 64 Bytes)
	 */

	#define chk(x) assert( !(x) ) /* if return value is not zero, abort */
	FOREIGN_DHKEYCHECK(idk1o);
	FOREIGN_DHKEYCHECK(ek1o);
	DHKEYCHECK(idk1s);
	DHKEYCHECK(ek1s);
	assert(salt);


	byte ek1[64], ek2[64], ek3[64], ek4[64];

	/* compute shared keys between ECDH Keys, including a salt*/
	chk(ECDH_hsalt(idk1o, idk1s, salt, ek1));
	chk(ECDH_hsalt(idk1o, ek1s, salt, ek2));
	chk(ECDH_hsalt(ek1o, idk1s, salt, ek3));
	chk(ECDH_hsalt(ek1o, ek1s, salt, ek4));

	/* xor ek2,ek3 to counter the inverse (ek2 will be ek3 for the other party) because the update order in sha512 matters */
	byte ek23[64];
	xor(ek2,ek3,64,ek23); 

	/* finalize shared secret using sha512 as a KDF*/
	sha512_context hctx;
	chk(sha512_init(&hctx));
	chk(sha512_update(&hctx, ek1, 64));
	chk(sha512_update(&hctx, ek23, 64));
	chk(sha512_update(&hctx, ek4, 64));
	chk(sha512_final(&hctx, secret));
}

void keyex_init(dhkey* idk1s, keyex_ctx* kctx)
{
	assert(idk1s && kctx);	
	memset(kctx,0x0,sizeof(keyex_ctx));

	dhkey* ctx_idk = &(kctx->idk1s);
	memcpy(ctx_idk,idk1s,sizeof(dhkey)); /* copy identity key */

	dhkey* ctx_ek = &(kctx->ek1s); /* generate new ephemeral key */
	ECDH_newkey("ek1s",ctx_ek);

	byte* ctx_ek_sig = kctx->sig_ek1s;
	ECDH_sign(ctx_idk, ctx_ek_sig, ctx_ek->pub, 32); /* sign public key */

	byte* ctx_salt = kctx->salt1s; /* generate 64Byte Salt */
	arc4random_buf(ctx_salt,64);

	byte* ctx_salt_sig = kctx->sig_salt1s;
	ECDH_sign(ctx_idk, ctx_salt_sig, ctx_salt, 64); /* generate signature for salt */

	/* set flags */
	kctx->allow_import_idk = 0;
	kctx->can_compute_secret = 0;
	kctx->err = 0;
	kctx->chkval = 0xFF;
}

void keyex_set_fidk(dhkey* idk1o, keyex_ctx* kctx)
{
	assert(idk1o && kctx && (kctx->chkval == 0xFF));

	dhkey* ctx_fidk = &(kctx->idk1o);
	memcpy(ctx_fidk,idk1o,sizeof(dhkey));
}

byte* keyex_infopacket(keyex_ctx* kctx)
{
	assert(kctx && (kctx->chkval = 0xFF));

	byte buf[256];	
	byte* wp = buf;

	memcpy(wp, &((kctx->idk1s).pub), 32); wp+=32;

	memcpy(wp, &((kctx->ek1s).pub), 32); wp+=32;

	memcpy(wp, kctx->sig_ek1s, 64);	wp+= 64;

	memcpy(wp, kctx->salt1s, 64); wp+= 64;

	memcpy(wp, kctx->sig_salt1s, 64);

	size_t sz = 0;
	return base64_encode(buf,256,&sz);
}

void keyex_process(byte* b64buf, keyex_ctx* kctx) /* expects buf NUL terminated */
{
	assert(b64buf && kctx && (kctx->chkval = 0xFF));

	size_t bufsz = 0;
	byte* buf = base64_decode(b64buf,strlen((const char*)b64buf),&bufsz);
	assert(bufsz == 256);

	dhkey* val_idk1o = &((kctx->idk1o)); /* validated key */

	byte* idk1o_pub = buf; /* 32B */
	byte* ek1o_pub = buf+32; /* 32B */
	byte* sig_ek1o_pub = buf+64; /* 64B */
	byte* salt1o = buf+128; /* 64B */
	byte* sig_salt1o = buf+192; /* 64B */

	if(kctx->allow_import_idk != 0){
		memcpy(val_idk1o->pub,idk1o_pub,32);
	} else {
		assert( !memcmp(val_idk1o->pub,idk1o_pub,32) );
	}
	assert( memcmp(kctx->salt1s,salt1o,64) ); /* make sure we dont select the same salt */

	/* check if valid signatures */
	assert(
		ECDH_verify(val_idk1o, sig_ek1o_pub, ek1o_pub, 32) &&
		ECDH_verify(val_idk1o, sig_salt1o, salt1o, 64)
	      );

	memcpy(&((kctx->ek1o).pub), ek1o_pub, 32);
	memcpy(kctx->salt1o, salt1o, 64);	

	kctx->can_compute_secret = 1;
	free(buf);
}

void keyex_compute(byte* sk_out, keyex_ctx* kctx){ /* sk_out min 64B */
	assert(kctx && (kctx->chkval == 0xFF) && (kctx->can_compute_secret == 1));
	
	byte xsalt[64]; /* xored salt values */
	xor(kctx->salt1s,kctx->salt1o,64,xsalt);

	keyex_calcsecret(&(kctx->idk1o), &(kctx->ek1o), &(kctx->idk1s), &(kctx->ek1s), xsalt, sk_out);
}

