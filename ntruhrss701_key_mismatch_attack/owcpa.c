#include "owcpa.h"
#include "sample.h"
#include "poly.h"
#include <stdio.h>
static int owcpa_check_r(const poly *r)
{
  /* Check that r is in message space. */
  /* Note: Assumes that r has coefficients in {0, 1, ..., q-1} */
  int i;
  uint64_t t = 0;
  uint16_t c;
  for(i=0; i<NTRU_N; i++)
  {
    c = MODQ(r->coeffs[i]+1);
    t |= c & (NTRU_Q-4);  /* 0 if c is in {0,1,2,3} */
    t |= (c + 1) & 0x4;   /* 0 if c is in {0,1,2} */
  }
  t |= r->coeffs[NTRU_N-1]; /* Coefficient n-1 must be zero */
  t = (-t) >> 63;
  return t;
}

#ifdef NTRU_HPS
static int owcpa_check_m(const poly *m)
{
  /* Check that m is in message space. */
  /* Note: Assumes that m has coefficients in {0,1,2}. */
  int i;
  uint64_t t = 0;
  uint16_t p1 = 0;
  uint16_t m1 = 0;
  for(i=0; i<NTRU_N; i++)
  {
    p1 += m->coeffs[i] & 0x01;
    m1 += (m->coeffs[i] & 0x02) >> 1;
  }
  /* Need p1 = m1 and p1 + m1 = NTRU_WEIGHT */
  t |= p1 ^ m1;
  t |= (p1 + m1) ^ NTRU_WEIGHT;
  t = (-t) >> 63;
  return t;
}
#endif

void owcpa_samplemsg(unsigned char msg[NTRU_OWCPA_MSGBYTES],
                     const unsigned char seed[NTRU_SAMPLE_RM_BYTES])
{
  poly r, m;

  sample_rm(&r, &m, seed);

  poly_S3_tobytes(msg, &r);
  poly_S3_tobytes(msg+NTRU_PACK_TRINARY_BYTES, &m);
}

void owcpa_keypair(unsigned char *pk,
                   unsigned char *sk,
                   const unsigned char seed[NTRU_SAMPLE_FG_BYTES],int G_real[701],int leng[1])
{
  int i;

  poly x1, x2, x3, x4, x5;

  poly *f=&x1, *invf_mod3=&x2;
  poly *g=&x3, *G=&x2;
  poly *Gf=&x3, *invGf=&x4, *tmp=&x5;
  poly *invh=&x3, *h=&x3;

  sample_fg(f,g,seed);

  poly_S3_inv(invf_mod3, f);
  poly_S3_tobytes(sk, f);
  poly_S3_tobytes(sk+NTRU_PACK_TRINARY_BYTES, invf_mod3);

  /* Lift coeffs of f and g from Z_p to Z_q */
  
  poly_Z3_to_Zq(f);
  poly_Z3_to_Zq(g);
  
  

#ifdef NTRU_HRSS
  /* G = 3*(x-1)*g */
  poly_Rq_mul_x_minus_1(G, g);
  
  for(int i=0;i<NTRU_N;i++)
{
       G_real[i]=G->coeffs[i];
 }
  
  //find the length of the longest consecutive chain(-2,2,-2,2...) of G to verify whether the first step is true or not
  int k = 1;
  int count = 1;
  int j;
 for( i = 1; i < NTRU_N; ++i )   
 {
  if((G->coeffs[i-1] == (8192-G->coeffs[i]))&&(G->coeffs[i-1]!=8191)&&(G->coeffs[i-1]!=1) )
  {++k;}
  else 
  {
   if( k > count )  
   {count = k;}
   k = 1;
  }
 }
 if( k > count )  
 {count = k;}

 for( i = 1, k = 1; i < NTRU_N; ++i )
 {
  if((G->coeffs[i-1] == (8192-G->coeffs[i]))&&(G->coeffs[i-1]!=8191)&&(G->coeffs[i-1]!=1) )
   ++k;
  else k = 1;
 }

 leng[0]=count;
  for(i=0; i<NTRU_N; i++)
    G->coeffs[i] = MODQ(3 * G->coeffs[i]);
#endif

#ifdef NTRU_HPS
  /* G = 3*g */
  for(i=0; i<NTRU_N; i++)
    G->coeffs[i] = MODQ(3 * g->coeffs[i]);
#endif

  poly_Rq_mul(Gf, G, f);

  poly_Rq_inv(invGf, Gf);

  poly_Rq_mul(tmp, invGf, f);
  poly_Sq_mul(invh, tmp, f);
  poly_Sq_tobytes(sk+2*NTRU_PACK_TRINARY_BYTES, invh);

  poly_Rq_mul(tmp, invGf, G);
  poly_Rq_mul(h, tmp, G);
  poly_Rq_sum_zero_tobytes(pk, h);
}


//first step :find the longest consecutive chain(-2,2,-2,2...) of G
void owcpa_enc(unsigned char *c,
               poly *rm,
               const unsigned char *pk,int j,int rj)
{
   int i;
  poly x1, x2, x3,x4,x5;
  poly *h = &x1, *liftm = &x1;
  poly *r = &x2, *m = &x2;
  poly *ct = &x3;

  poly_Rq_sum_zero_frombytes(h, pk);


for(i=0;i<j;i++)
{

  if(j>=10)
{
 if((i%2)==0)r->coeffs[i]=3*rj;
 else r->coeffs[i]=8192-3*rj;
}

else
{
  if((i%2)==0)r->coeffs[i]=4*rj;
 else r->coeffs[i]=8192-4*rj;
}

}

for(i=j;i<NTRU_N;i++)
   r->coeffs[i]=0;
  
  

  poly_Rq_mul(ct, r, h);

  
   for(i=0; i<NTRU_N; i++)
    m->coeffs[i] = 0;

for(i=0; i<NTRU_N; i++)
    rm->coeffs[i] = m->coeffs[i];

  poly_lift(liftm, m);
  for(i=0; i<NTRU_N; i++)
    ct->coeffs[i] = MODQ(ct->coeffs[i] + liftm->coeffs[i]);


 
  poly_Rq_sum_zero_tobytes(c, ct);
}


//third step :find (-2,-1,0) or (0,1,2) or (-1,0,1)
void owcpa_enc0(unsigned char *c,
               poly *rm,
               const unsigned char *pk,int j,int j0,int rj,int rj0,int same[701],int p2,int ss[701])
{
  int i;
  poly x1, x2, x3,x4,x5;
  poly *h = &x1, *liftm = &x1;
  poly *r = &x2, *m = &x2;
  poly *ct = &x3;

  poly_Rq_sum_zero_frombytes(h, pk);

 
  for(i=0; i<NTRU_N; i++)
    r->coeffs[i] =0;

 for(i=0;i<15;i++)
{
  if(same[i]==-3)break;

if(same[i]==-2){r->coeffs[i]=p2*rj;}
else if(same[i]==2){r->coeffs[i]=8192-p2*rj;}
else if(same[i]==1){r->coeffs[i]=8192-rj;}
else if(same[i]==-1){r->coeffs[i]=rj;}
else if(same[i]==0){r->coeffs[i]=r->coeffs[i-1]>4096?(8192-rj):rj;}
}


 for(i=0;i<NTRU_N;i++)
{
  if(ss[i]==-3)break;

r->coeffs[ss[i]+j-1]=rj;
}


r->coeffs[j-1+j0]=rj0;

  
 

  poly_Rq_mul(ct, r, h);


   for(i=0; i<NTRU_N; i++)
    m->coeffs[i] = 0;

for(i=0; i<NTRU_N; i++)
    rm->coeffs[i] = m->coeffs[i];

  poly_lift(liftm, m);
  for(i=0; i<NTRU_N; i++)
    ct->coeffs[i] = MODQ(ct->coeffs[i] + liftm->coeffs[i]);


 
  poly_Rq_sum_zero_tobytes(c, ct);
}


//second step :find (-2,0) or (0,-2) or (2,0) or (0,2)
void owcpa_enc1(unsigned char *c,
               poly *rm,
               const unsigned char *pk,int j,int j0,int rj,int rj0,int same[701],int p2,int ss[701])
{
  int i;
  poly x1, x2, x3,x4,x5;
  poly *h = &x1, *liftm = &x1;
  poly *r = &x2, *m = &x2;
  poly *ct = &x3;

  poly_Rq_sum_zero_frombytes(h, pk);

  for(i=0; i<NTRU_N; i++)
    r->coeffs[i] =0;
 

 for(i=0;i<15;i++)
{
  if(same[i]==-3)break;

if(same[i]==-2){r->coeffs[i]=p2*rj;}
else if(same[i]==2){r->coeffs[i]=8192-p2*rj;}
else if(same[i]==1){r->coeffs[i]=8192-rj;}
else if(same[i]==-1){r->coeffs[i]=rj;}
else if(same[i]==0){r->coeffs[i]=r->coeffs[i-1]>4096?(8192-rj):rj;}
}



 for(i=0;i<NTRU_N;i++)
{
  if(ss[i]==-3)break;

  r->coeffs[ss[i]+j-1]=rj;
}





 if(rj==rj0)
{
r->coeffs[j-1+j0]=p2*rj;
r->coeffs[j-1+j0+1]=rj0;
}

else if(rj0==p2*rj)
{
r->coeffs[j-1+j0]=rj;
r->coeffs[j-1+j0+1]=rj0;
}

else if((rj+rj0)==8192)
{
 r->coeffs[j-1+j0]=8192-p2*rj;
 r->coeffs[j-1+j0+1]=rj0;
}

else if((p2*rj+rj0)==8192)
{
 r->coeffs[j-1+j0]=8192-rj;
 r->coeffs[j-1+j0+1]=rj0;
}


 

  poly_Rq_mul(ct, r, h);

 
   for(i=0; i<NTRU_N; i++)
    m->coeffs[i] = 0;

for(i=0; i<NTRU_N; i++)
    rm->coeffs[i] = m->coeffs[i];

  poly_lift(liftm, m);
  for(i=0; i<NTRU_N; i++)
    ct->coeffs[i] = MODQ(ct->coeffs[i] + liftm->coeffs[i]);


 
  poly_Rq_sum_zero_tobytes(c, ct);
}


int owcpa_dec(poly *rm,
              const unsigned char *ciphertext,
              const unsigned char *secretkey)
{
  int i;
  int fail;
  poly x1, x2, x3, x4;

  poly *c = &x1, *f = &x2, *cf = &x3;
  poly *mf = &x2, *finv3 = &x3, *m = &x4;
  poly *liftm = &x2, *invh = &x3, *r = &x4;
  poly *b = &x1;

  poly_Rq_sum_zero_frombytes(c, ciphertext);
  poly_S3_frombytes(f, secretkey);
  poly_Z3_to_Zq(f);

  poly_Rq_mul(cf, c, f);
  
  poly_Rq_to_S3(mf, cf);
  
   
  
  

  poly_S3_frombytes(finv3, secretkey+NTRU_PACK_TRINARY_BYTES);
  poly_S3_mul(m, mf, finv3);
  
  for(i=0; i<NTRU_N; i++)
    rm->coeffs[i] = m->coeffs[i];

  fail = 0;
#ifdef NTRU_HPS
  fail |= owcpa_check_m(m);
#endif

  /* b = c - Lift(m) mod (q, x^n - 1) */
  poly_lift(liftm, m);
  for(i=0; i<NTRU_N; i++)
    b->coeffs[i] = MODQ(c->coeffs[i] - liftm->coeffs[i]);

  /* r = b / h mod (q, Phi_n) */
  poly_Sq_frombytes(invh, secretkey+2*NTRU_PACK_TRINARY_BYTES);
  poly_Sq_mul(r, b, invh);
  fail |= owcpa_check_r(r);

  poly_trinary_Zq_to_Z3(r);

  return fail;
}

