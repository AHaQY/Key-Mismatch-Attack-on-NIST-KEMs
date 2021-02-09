#ifndef API_H
#define API_H

#include "params.h"
#include "poly.h"
#define CRYPTO_SECRETKEYBYTES NTRU_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES NTRU_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES NTRU_CIPHERTEXTBYTES
#define CRYPTO_BYTES NTRU_SHAREDKEYBYTES

#define CRYPTO_ALGNAME "NTRU-HRSS701"

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk,int G_real[701],int leng[1]);

int crypto_kem_enc(unsigned char *ct, poly *ss, const unsigned char *pk,int j,int rj);
int crypto_kem_enc0(unsigned char *ct, poly *ss, const unsigned char *pk,int j,int j0,int rj,int rj0,int same[701],int p2,int s[701]);
int crypto_kem_enc1(unsigned char *ct, poly *ss, const unsigned char *pk,int j,int j0,int rj,int rj0,int same[701],int p2,int s[701]);


int crypto_kem_dec(poly *ss, const unsigned char *ct, const unsigned char *sk);


#endif
