CC=gcc
CFLAGS= -I. -I./curve25519 -I./base64 -I./sec -I./serial -lbsd -DDEBUG -Wall -Wextra -Werror -g3 -O3
OBJ =  curve25519/add_scalar.o curve25519/fe.o curve25519/ge.o curve25519/key_exchange.o curve25519/keypair.o curve25519/sc.o curve25519/sha512.o curve25519/sign.o curve25519/verify.o examples/main.o curve25519/seed.o sec/ecdh_base.o base64/base64.o sec/ecdh_keyex.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)
crypt0.bin: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)
clean:
	rm -rf curve25519/*.o sec/*.o base64/*.o 
