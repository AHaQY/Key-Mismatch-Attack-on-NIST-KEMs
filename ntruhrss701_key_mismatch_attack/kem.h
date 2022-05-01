#ifndef NTRUKEM_H
#define NTRUKEM_H

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk,int leng[1],int recording[10]);

int crypto_kem_enc(unsigned char *c, poly *k, const unsigned char *pk,int j,int rj);
int crypto_kem_enc0(unsigned char *c, poly *k, const unsigned char *pk,int j,int j0,int rj,int rj0,int same[701],int p2,int s[701]);

int crypto_kem_enc1(unsigned char *c, poly *k, const unsigned char *pk,int j,int j0,int rj,int rj0,int same[701],int p2,int s[701]);

int crypto_kem_dec(poly *k, const unsigned char *c, const unsigned char *sk);

#endif
