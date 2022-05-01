#ifndef OWCPA_H
#define OWCPA_H
#include "poly.h"
#include "params.h"

void owcpa_samplemsg(unsigned char msg[NTRU_OWCPA_MSGBYTES],
                     const unsigned char seed[NTRU_SEEDBYTES]);

void owcpa_keypair(unsigned char *pk,
                   unsigned char *sk,
                   const unsigned char seed[NTRU_SEEDBYTES],int G_real[701],int leng[1],int recording[10]);

void owcpa_enc(unsigned char *c,
               poly *rm,
               const unsigned char *pk,int j,int rj);
			   
void owcpa_enc0(unsigned char *c,
               poly *rm,
               const unsigned char *pk,int j,int j0,int rj,int rj0,int same[701],int p2,int ss[701]);
void owcpa_enc1(unsigned char *c,
               poly *rm,
               const unsigned char *pk,int j,int j0,int rj,int rj0,int same[701],int p2,int ss[701]);
			   

int owcpa_dec(poly *rm,
              const unsigned char *c,
              const unsigned char *sk);
#endif
