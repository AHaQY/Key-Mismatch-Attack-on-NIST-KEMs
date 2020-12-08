#include "SABER_params.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "SABER_indcpa.h"
#include "api.h"
#include "verify.h"
#include "rng.h"
#include "fips202.h"


int crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{                                                                    
  indcpa_kem_keypair(pk, sk); 		// sk[0:SABER_INDCPA_SECRETKEYBYTES-1] <-- sk															  
  return (0);
}

int crypto_kem_enc(unsigned char *c, unsigned char *k, const unsigned char *pk)
{
  unsigned char kr[32];                           
  unsigned char buf[32];  
  int random,i;
  random=rand()%100; 
  for(i=0;i<random;i++)  
  {
     randombytes(buf, 32);
     randombytes(kr, 32);
  }
                      
  indcpa_kem_enc(buf, kr, pk,  c);// buf[0:31] contains message; kr[0:31] contains randomness r;
  memcpy(k,buf,32);
  return (0);
}

int crypto_kem_dec(unsigned char *k, const unsigned char *c, const unsigned char *sk)
{
  unsigned char buf[32];
  indcpa_kem_dec(sk, c, buf);    // buf[0:31] <-- message
  memcpy(k,buf,32);
  return (0);
}
