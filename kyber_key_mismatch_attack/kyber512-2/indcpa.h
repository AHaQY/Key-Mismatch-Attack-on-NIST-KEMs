#ifndef INDCPA_H
#define INDCPA_H


#include "polyvec.h"

void indcpa_keypair(unsigned char *pk,
                    unsigned char *sk,
                    polyvec * skpoly);

void indcpa_enc(unsigned char *c,
                const unsigned char *m,
                const unsigned char *pk,
                const unsigned char *coins);

void indcpa_dec(unsigned char *m,
                const unsigned char *c,
                const unsigned char *sk);


//oracle
void enc(unsigned char * c, 
         const unsigned char * m, 
         int h, int k, int select);


#endif
