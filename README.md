# Curve25519 Key-Exchange in C
## Small & PFS


### Example

  Both Alice & Bob complete 6 steps:
 
  1. Generate identity key / load from file -- ECDH_newkey()
  2. Initialize Key Context using identity key -- keyex_init()
  3. Load Partner Identity Key to protect against MiTM -- keyex_set_fidk()
  4. Generate Information Packet and send to Partner -- keyex_infopacket()
  5. Process Partner Information Packet -- keyex_process()
  6. Compute Derived Hashed 64Byte Shared Secret Key (128bit strength) -- keyex_compute()
 
 For sample code look at examples/main.c
 
 ### Computing the shared key 
 
 Both Alice & Bob have:
 
     PartnerSalt, 
     SelfSalt,
     IdentityKeyPartner(Public), 
     IdentiyKeySelf(Public/Private),
     EphemeralKeyPartner(Public), 
     EphemeralKeySelf(Public/Private)
  
  
 Both Compute:
 
      Salt = XOR(PartnerSalt, SelfSalt)
      K1 = ECDH_hash_salt(IdentityKeyPartner, IdentityKeySelf, Salt)
      K2 = ECDH_hash_salt(IdentityKeyPartner, EphemeralKeySelf, Salt)
      K3 = ECDH_hash_salt(EphemeralKeyPartner, IdentityKeySelf, Salt)
      K4 = ECDH_hash_salt(EphemeralKeyPartner, EphemeralKeySelf, Salt)
      K23 = XOR(K2, K3) // Counter Inversion
      
      SHARED_KEY = SHA512(K1 | K23 | K4)
      
  ** ECDH_hash_salt(k1, k2, salt) returns SHA512( ECDH(k1,k2) | salt) **
