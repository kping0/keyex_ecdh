
/* 
 * --Summary--
 * Each User completes 6 steps:
 *
 * 1. Generate identity key / load from file -- ECDH_newkey()
 * 2. Initialize Key Context using identity key -- keyex_init()
 * 3. Load Partner Identity Key to protect against MiTM -- keyex_set_fidk()
 * 4. Generate Information Packet and send to Partner -- keyex_infopacket()
 * 5. Process Partner Information Packet -- keyex_process()
 * 6. Compute Derived Hashed 64Byte Shared Secret Key (128bit strength) -- keyex_compute()
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <bsd/stdlib.h>
#include <string.h>
#include "ecdh_keyex.h"

typedef unsigned char byte;

int main(int argc, char** argv){

	/* we dont need arguments */
	(void)argv;
	(void)argc;

	/* initialize variables */
	byte sk1[64], sk2[64];
	dhkey idk1o,idk1s;
	keyex_ctx kctx, kctx2;

	ECDH_newkey("idk1o",&idk1o); /* user1 generates identity key */
	ECDH_newkey("idk1s",&idk1s);  /* user2 ' */

	keyex_init(&idk1s,&kctx); /* user1 generates key context (including generating ephemeral key) */
	keyex_init(&idk1o,&kctx2); /* user2 ' */

	keyex_set_fidk(&idk1o,&kctx); /* user1 sets partners foreign identity key (anti mitm) */
	keyex_set_fidk(&idk1s,&kctx2); /* user2 ' */

	byte* buf1 = keyex_infopacket(&kctx); /* user1 generates keyexchange information packet and somehow communicates it to partner */
	byte* buf2 = keyex_infopacket(&kctx2); /* user2 ' */

	keyex_process(buf2,&kctx); /* user1 processes partners infopacket */
	keyex_process(buf1,&kctx2); /* user2 ' */

	keyex_compute(sk1,&kctx); /* user1 computes shared key based on infopacket of partner */
	keyex_compute(sk2,&kctx2); /* user2 ' */
	
	/* dump seperately calculated 64Byte Keys */

	hexdump(sk1,64);
	hexdump(sk2,64); 

	if(memcmp(sk1,sk2,64) == 0){
		printf("\nKeys match. Key Exchange Complete.\n");
	} else {
		printf("\nKeys do not match. Failed Key Exchange.\n");
	}

	/* free heap structures */
	free(buf1);
	free(buf2);

	return 0;
}

