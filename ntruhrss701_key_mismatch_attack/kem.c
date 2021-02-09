#include "rng.h"
#include "fips202.h"
#include "params.h"
#include "verify.h"
#include "owcpa.h"
#include<time.h>
#include<stdio.h>
#include<stdlib.h>

// API FUNCTIONS 
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk,int G_real[701],int leng[1])
{
  unsigned char seed[NTRU_SAMPLE_FG_BYTES];
  srand((int)time(0));
  int j=1+(int)(10000.0*rand()/(RAND_MAX+1.0));
  for (int i=0; i<j; i++) 
  {
      randombytes(seed, NTRU_SAMPLE_FG_BYTES);
   }
  owcpa_keypair(pk, sk, seed,G_real,leng);


  return 0;
}


//find (-2,2,-2,2....)
int crypto_kem_enc(unsigned char *c, poly *k, const unsigned char *pk,int j,int rj)
{

  owcpa_enc(c, k, pk,j,rj);

  return 0;
}

//find (-2,0) or (0,-2) or (2,0) or (0,2)
int crypto_kem_enc0(unsigned char *c, poly *k, const unsigned char *pk,int j,int j0,int rj,int rj0,int same[701],int p2,int s[701])
{

  owcpa_enc0(c, k, pk,j,j0,rj,rj0,same,p2,s);

  return 0;
}


//find (-2,-1,0) or  (0,1,2) or (-1,0,1)
int crypto_kem_enc1(unsigned char *c, poly *k, const unsigned char *pk,int j,int j0,int rj,int rj0,int same[701],int p2,int s[701])
{

  owcpa_enc1(c, k, pk,j,j0,rj,rj0,same,p2,s);

  return 0;
}




int crypto_kem_dec(poly *k, const unsigned char *c, const unsigned char *sk)
{
  int i, fail;

  fail = owcpa_dec(k, c, sk);
  return 0;
}
