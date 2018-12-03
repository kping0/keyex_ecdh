#include "ecdh_base.h"

#ifdef DEBUG
void hexdump(byte* mem, size_t len){
	printf("-- HEX DUMP (%zu bytes) for 0x%p --\n",len,mem);
	int x = 0;
	for(size_t i = 0; i < len; i++){
		printf("0x%x ",mem[i]);
		x++;
		if(x == 15){
			printf("\n");	
			x = 0;
		}
	}
	printf("\n -- END HEX DUMP --\n"); 
}
#endif

void ECDH(byte* public, byte* private, byte* secret_out)
{
	assert(public && private && secret_out);
	/* calculate DH secret */
	curve25519_key_exchange(secret_out,public,private);
	return;
}

int ECDH_hsalt(dhkey* foreignkey, dhkey* ownkey, byte* salt, byte* hash_out) /* foreignkey, ownkey, 64B salt, 128B out buffer for secret */
{
	DHKEYCHECK(ownkey);
	FOREIGN_DHKEYCHECK(foreignkey);
	assert(salt && hash_out);

	byte* public = foreignkey->pub;
	byte* private = ownkey->priv;

	byte secret[32];
	ECDH(public,private,secret);

	int rv;

	/* hash DH secret + salt */
	sha512_context hctx;
	if( (rv = sha512_init(&hctx)) ) return rv;
	if( (rv = sha512_update(&hctx, salt, 64)) ) return rv;
	if( (rv = sha512_update(&hctx, secret, 32)) ) return rv;
	if( (rv = sha512_final(&hctx, hash_out)) ) return rv;
	
	return 0;

}

int ECDH_loadkey(const char* name, byte* pub, byte* priv, dhkey* key_out)
{
	DHKEYCHECK(key_out);
	assert(name && pub);

	int namesz = strlen(name);
	if(namesz > 31)return 1;

	memcpy(key_out->pub,pub,32);
	if(priv != NULL)memcpy(key_out->priv,priv,64);
	memcpy(key_out->name, name, namesz);
	key_out->name[namesz] = 0x0;

	return 0;
}

#ifdef DEBUG
void ECDH_dumpkey(dhkey* key)
{
	fprintf(stdout,"\n\n-- KEY DUMP (name: %s) at 0x%p --\n",key->name,key);

	fprintf(stdout,"\n--PUBLIC KEY--\n\n");
	hexdump(key->pub,32);
	fprintf(stdout,"\n--END PUBLIC KEY--\n\n");

	fprintf(stdout,"\n--PRIVATE KEY--\n\n");
	hexdump(key->priv,64);
	fprintf(stdout,"\n--END PRIVATE KEY--\n\n");

	fprintf(stdout,"-- END KEY DUMP --\n");

	return;
}
#endif

int ECDH_newkey(const char* name, dhkey* key) /* requires: name(max 31), key out struct */
{
	DHKEYCHECK(key);
	assert(name);

	byte* public = key->pub;
	byte* private = key->priv;
	byte* namebuf = key->name;
	byte seed[32];	

	if(curve25519_create_seed(seed))return 1;
	curve25519_create_keypair(public,private,seed); /* generate keypair */

	size_t namesz = strlen(name);
	if(namesz > 31){
		fprintf(stderr,"ERROR: ECDH KeyName needs to be <31 Bytes\n");
		return 2;
	}
	memcpy(namebuf, name, namesz);
	namebuf[namesz] = 0x0;

	return 0;
}

int ECDH_verify(dhkey* idk1o, byte* sig, byte* buf, size_t bufsz)
{
	DHKEYCHECK(idk1o);
	assert(sig && buf && (bufsz > 0));

	byte* pub = idk1o->pub;
	byte* name = idk1o->name;
	if( curve25519_verify(sig, buf, bufsz, pub) ){
		return 1;	
	} else {
		fprintf(stderr,"WARNING: invalid signature for key (%s)\n",name);
		return 0;
	}
}

int ECDH_sign(dhkey* idk1s, byte* sig, byte* buf, size_t bufsz)
{
	DHKEYCHECK(idk1s);
	assert(sig && buf && (bufsz > 0));

	byte* pub = idk1s->pub;
	byte* priv = idk1s->priv;	

	curve25519_sign(sig,buf,bufsz, pub, priv);

	return 0;
}
