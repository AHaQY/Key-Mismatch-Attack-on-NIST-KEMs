/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: benchmarking/testing KEM scheme
*********************************************************************************************/

#define KEM_TEST_ITERATIONS 1
#define KEM_BENCH_SECONDS     1
#define PARAMS_N 640
#define PARAMS_NBAR 8
#define PARAMS_LOGQ 15
#define PARAMS_Q (1 << PARAMS_LOGQ)
#include "../src/util.c"
#include <sys/time.h>


static int kem_attack() 
{  //key mismatch attack on Frodo640
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
    int flag,cnt=0;

       crypto_kem_keypair(pk, sk);
        for(int j=0;j<640;j++)
      {
        memset(Bp,0,sizeof(Bp));
        Bp[j] = 1;
        frodo_pack(ct_c1, (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8, Bp, PARAMS_N*PARAMS_NBAR, PARAMS_LOGQ);
        for(int k=0;k<8;k++)
       {
        memset(C,0,sizeof(C));
        C[k]=4096;
		cnt++;
        frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
        flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
        if(flag==0)
        {       
        C[k]=4096-2;
		cnt++;
        frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
        flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);	
          if(flag==1)
         {
           C[k]=4096-1;
		   cnt++;
           frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
           flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
           if(flag==1)
          {
            S[j*PARAMS_NBAR+k]=0;
          }
           else
          { 
            S[j*PARAMS_NBAR+k]=32768-1;
          }
         }
         else
         {
           C[k]=4096-3;
		   cnt++;
           frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
           flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
           if(flag==1)
          {
            S[j*PARAMS_NBAR+k]=32768-2;
          }
          else
          { 
           C[k]=4096-4;
		   cnt++;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
            if(flag==1)
           {
            S[j*PARAMS_NBAR+k]=32768-3;
           }
           else
           {
            C[k]=4096-5;
			cnt++;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
            if(flag==1)
           {
            S[j*PARAMS_NBAR+k]=32768-4;
           }
           else
           {
            C[k]=4096-6;
			cnt++;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
            if(flag==1)
           {
            S[j*PARAMS_NBAR+k]=32768-5;
           }
            else
            {
            C[k]=4096-7;
			cnt++;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
            if(flag==1)
           {
            S[j*PARAMS_NBAR+k]=32768-6;
           }
            else
            {
            C[k]=4096-8;
			cnt++;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
            if(flag==1)
            {
            S[j*PARAMS_NBAR+k]=32768-7;
            }
            else
            {
            C[k]=4096-9;
			cnt++;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
            if(flag==1)
           {
            S[j*PARAMS_NBAR+k]=32768-8;
           }
            else
            {
             C[k]=4096-10;
			 cnt++;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
            if(flag==1)
           {
            S[j*PARAMS_NBAR+k]=32768-9;
           }
            else
            {
            C[k]=4096-11;
			cnt++;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
            if(flag==1)
           {
            S[j*PARAMS_NBAR+k]=32768-10;
           }
            else
            {
            C[k]=4096-12;
			cnt++;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
            if(flag==1)
           {
            S[j*PARAMS_NBAR+k]=32768-11;
           }
           else
            {
             S[j*PARAMS_NBAR+k]=32768-12;
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

        }
        
        else
        {
         C[k]=4096+2;
		 cnt++;
        frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
        flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);     
          if(flag==0)
         {
           C[k]=4096+1;
		   cnt++;
           frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
           flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
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
		   cnt++;
           frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
           flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
           if(flag==0)
          {
            S[j*PARAMS_NBAR+k]=3;
          }
          else
          { 
           C[k]=4096+4;
		   cnt++;
		   frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
            if(flag==0)
           {
            S[j*PARAMS_NBAR+k]=4;
           }
           else
           {
            C[k]=4096+5;
			cnt++;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
            if(flag==0)
           {
            S[j*PARAMS_NBAR+k]=5;
           }
           else
           {
            C[k]=4096+6;
			cnt++;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
            if(flag==0)
           {
            S[j*PARAMS_NBAR+k]=6;
           }
            else
            {
            C[k]=4096+7;
			cnt++;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
            if(flag==0)
           {
            S[j*PARAMS_NBAR+k]=7;
           }
            else
            {
            C[k]=4096+8;
			cnt++;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
            if(flag==0)
            {
            S[j*PARAMS_NBAR+k]=8;
            }
            else
            {
            C[k]=4096+9;
			cnt++;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
            if(flag==0)
           {
            S[j*PARAMS_NBAR+k]=9;
           }
            else
            {
             C[k]=4096+10;
			 cnt++;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
            if(flag==0)
           {
            S[j*PARAMS_NBAR+k]=10;
           }
            else
            {
            C[k]=4096+11;
			cnt++;
            frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
            flag=crypto_kem_dec(ss_encap,ss_decap, ct, sk);
            if(flag==0)
           {
            S[j*PARAMS_NBAR+k]=11;
           }
            else
            {
             S[j*PARAMS_NBAR+k]=12;
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


       }
      }
    
        









   
   
    for(int j=0;j<PARAMS_N*PARAMS_NBAR;j++)
    {
      sk_S[j]=sk_S[j]%32768;
    }
    if(memcmp(S,sk_S,PARAMS_N*PARAMS_NBAR)==0){ return cnt;}
    else {return 99999;}
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
