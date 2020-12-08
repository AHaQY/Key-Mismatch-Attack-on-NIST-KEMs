/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: benchmarking/testing KEM scheme
*********************************************************************************************/

#define KEM_TEST_ITERATIONS 1
#define KEM_BENCH_SECONDS     1
#define PARAMS_N 976
#define PARAMS_NBAR 8
#define PARAMS_LOGQ 16
#define PARAMS_Q (1 << PARAMS_LOGQ)
#include "../src/util.c"
#include <sys/time.h>

static int kem_attack() 
{
	//key mismatch attack on Frodo976
   //  parameters: Bp: c1
   //              C : c2
   //        ss_encap: message
   //            flag: Oracle's output
   //	          cnt: count the total queries
		
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ss_encap[CRYPTO_BYTES]={0};
    uint8_t ss_decap[CRYPTO_BYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t *ct_c1 = &ct[0];
    uint8_t *ct_c2 = &ct[(PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8];
    uint16_t C[PARAMS_NBAR*PARAMS_NBAR] = {0};
    uint16_t Bp[PARAMS_N*PARAMS_NBAR]= {0};
    uint16_t S[PARAMS_N*PARAMS_NBAR];
    uint16_t *sk_S = (uint16_t *) &sk[0];
    int flag,query=0;

        crypto_kem_keypair(pk, sk);
        //crypto_kem_enc(ct, ss_encap, pk);
        for(int j=0;j<976;j++)
      {
        memset(Bp,0,sizeof(Bp));
        Bp[j] = 1;
        frodo_pack(ct_c1, (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8, Bp, PARAMS_N*PARAMS_NBAR, PARAMS_LOGQ);
        for(int k=0;k<8;k++)
       {
        //printf("--%d---\n\n",k);
        memset(C,0,sizeof(C));
        C[k]=4096;
        frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
        flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
		query++;
        if(flag==0)
        {       
        C[k]=4096-2;
        frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
        flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
        query++;		
          if(flag==1)
         {
           C[k]=4096-1;
           frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
           flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
		   query++;
           if(flag==1)
          {
            S[j*PARAMS_NBAR+k]=0;
          }
           else
          { 
            S[j*PARAMS_NBAR+k]=65536-1;
          }
         }
         else
         {
           C[k]=4096-3;
           frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
           flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
		   query++;
           if(flag==1)
          {
            S[j*PARAMS_NBAR+k]=65536-2;
          }
          else
          { 
           C[k]=4096-4;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
			query++;
            if(flag==1)
           {
            S[j*PARAMS_NBAR+k]=65536-3;
           }
           else
           {
            C[k]=4096-5;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
			query++;
            if(flag==1)
           {
            S[j*PARAMS_NBAR+k]=65536-4;
           }
           else
           {
            C[k]=4096-6;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
			query++;
            if(flag==1)
           {
            S[j*PARAMS_NBAR+k]=65536-5;
           }
            else
            {
            C[k]=4096-7;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
			query++;
            if(flag==1)
           {
            S[j*PARAMS_NBAR+k]=65536-6;
           }
            else
            {
            C[k]=4096-8;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
			query++;
            if(flag==1)
            {
            S[j*PARAMS_NBAR+k]=65536-7;
            }
            else
            {
            C[k]=4096-9;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
			query++;
            if(flag==1)
           {
            S[j*PARAMS_NBAR+k]=65536-8;
           }
            else
            {
             C[k]=4096-10;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
			query++;
            if(flag==1)
           {
            S[j*PARAMS_NBAR+k]=65536-9;
           }
            else
            {
            S[j*PARAMS_NBAR+k]=65536-10;
            }
            }
            }
            }
            }
           }
           }
          }
         }

        }
        
        else
        {
         C[k]=4096+2;
        frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
        flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);  
        query++;		
          if(flag==0)
         {
           C[k]=4096+1;
           frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
           flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
		   query++;
           if(flag==0)
          {
            S[j*PARAMS_NBAR+k]=1;
          }
           else
          { 
            S[j*PARAMS_NBAR+k]=2;
          }
         }
         else
         {
           C[k]=4096+3;
           frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
           flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
		   query++;
           if(flag==0)
          {
            S[j*PARAMS_NBAR+k]=3;
          }
          else
          { 
           C[k]=4096+4;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
			query++;
            if(flag==0)
           {
            S[j*PARAMS_NBAR+k]=4;
           }
           else
           {
            C[k]=4096+5;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
			query++;
            if(flag==0)
           {
            S[j*PARAMS_NBAR+k]=5;
           }
           else
           {
            C[k]=4096+6;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
			query++;
            if(flag==0)
           {
            S[j*PARAMS_NBAR+k]=6;
           }
            else
            {
            C[k]=4096+7;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
			query++;
            if(flag==0)
           {
            S[j*PARAMS_NBAR+k]=7;
           }
            else
            {
            C[k]=4096+8;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
			query++;
            if(flag==0)
            {
            S[j*PARAMS_NBAR+k]=8;
            }
            else
            {
            C[k]=4096+9;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
			query++;
            if(flag==0)
           {
            S[j*PARAMS_NBAR+k]=9;
           }
            else
            {
            S[j*PARAMS_NBAR+k]=10;
            }
            }
            }
            }
           }
           }
          }
         }
        }


       }
      }
    
        









   
   
    for(int j=0;j<PARAMS_N*PARAMS_NBAR;j++)
    {
      sk_S[j]=sk_S[j]%65536;
    }
   if(memcmp(S,sk_S,PARAMS_N*PARAMS_NBAR)==0){return query;}
   else return 99999;
}


int main() 
{
    // calculate the average time and average queries of 10000 times
    struct timeval tv1,tv2;
    int count,query=0;
    gettimeofday(&tv1,NULL);
    srand(time(NULL));
    for(count=0;count<10000;count++)
   { 
    query+=kem_attack();
   }
	gettimeofday(&tv2,NULL);
    printf("total time:%.4fs\n",((double)(tv2.tv_sec-tv1.tv_sec)*1000+(double)(tv2.tv_usec-tv1.tv_usec)/1000)/1000);
   printf("total_average time:%.4fs\n",(((double)(tv2.tv_sec-tv1.tv_sec)*1000+(double)(tv2.tv_usec-tv1.tv_usec)/1000)/1000)/10000);
  printf("total_average queries:%.4f\n",(double)(query/10000.0));
	return 0;
}
