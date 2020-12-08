#include "../api.h"
#include "../poly.h"
#include "../rng.h"
#include "../SABER_indcpa.h"
#include "../verify.h"
#include "../pack_unpack.h"
#include<stdio.h>
#include<stdint.h>
#include<string.h>
#include <sys/time.h>


static int test_pke_cpa()
{
	//key mismatch attack on Saber
   // parameters: res: b'
   //          vprime: cm
   //            ss_a: message
   //	        query: count the total queries
		

  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];	
  uint8_t ss_a[CRYPTO_BYTES], ss_b[CRYPTO_BYTES];
  
  	uint16_t res[SABER_L][SABER_N],sk_hat[SABER_L][SABER_N];
	uint16_t vprime[SABER_N];
	uint16_t sksv[SABER_L][SABER_N]; //secret key of the server
	int query=0;
  unsigned char entropy_input[48];
	
 int i,j,k,cnt;


   
    	for (i=0; i<48; i++)
        	entropy_input[i] = i;
     
              randombytes_init(entropy_input, NULL, 256);




	    //Generation of secret key sk and public key pk pair
	    crypto_kem_keypair(pk, sk);
        BS2POLVECq(sk, sksv); //sksv is the secret-key
		 
		 
		 for(i=0;i<SABER_L;i++)
		{
         memset(ss_a,0,sizeof(ss_a));
	     ss_a[0]=1;
		 memset(vprime,0,sizeof(vprime));			
		 for(k=0;k<SABER_N;k++)
	     {
			 memset(res,0,sizeof(res));
			 if(k==0){res[i][k]=4;}
			 else {res[i][SABER_N-k]=1024-4;}
			 
			 POLVECp2BS(ct, res);
			
			 vprime[0]=16;
			 POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
			   
			  //Key-Decapsulation call; input: sk, c; output: shared-secret ss_b;	
		     // It plays a role of Oracle on launching key mismatch attack 	
	          crypto_kem_dec(ss_b, ct, sk);
	          query++;

	          for(cnt=0; cnt<SABER_KEYBYTES; cnt++)
	          {
		         if(ss_a[cnt] != ss_b[cnt])
		      {
			       break;
		      }
			  
	          }
			  

			  if(cnt==SABER_KEYBYTES)
			  {
		    
			 if(k==0){res[i][k]=13;}
			 else {res[i][SABER_N-k]=1024-13;}
			 POLVECp2BS(ct, res); 
			 
			
			 vprime[0]=15;
			 POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
			   
	          crypto_kem_dec(ss_b, ct, sk);
	         query++;

	          for(cnt=0; cnt<SABER_KEYBYTES; cnt++)
	          {
		         if(ss_a[cnt] != ss_b[cnt])
		      {
			       break;
		      }
			  
	          }
			  
			  if(cnt!=SABER_KEYBYTES)
			  {
				  sk_hat[i][k]=0;
			  }
			  
			  else 
			  {
			 if(k==0){res[i][k]=12;}
			 else {res[i][SABER_N-k]=1024-12;}
			 POLVECp2BS(ct, res);
			 
			
			 vprime[0]=15;
			 POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
			   
	          crypto_kem_dec(ss_b, ct, sk);
	          query++;
	          for(cnt=0; cnt<SABER_KEYBYTES; cnt++)
	          {
		         if(ss_a[cnt] != ss_b[cnt])
		      {	
			       break;
		      }
			  
	          }
				
               if(cnt!=SABER_KEYBYTES)
			  {
				  sk_hat[i][k]=8192-1;
			  }
			  
			  else
			  {
				  if(k==0){res[i][k]=6;}
			      else {res[i][SABER_N-k]=1024-6;}
			     POLVECp2BS(ct, res); 
			 
			
			 vprime[0]=15;
			POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
			   
			   
	          crypto_kem_dec(ss_b, ct, sk);
	          query++;

	          for(cnt=0; cnt<SABER_KEYBYTES; cnt++)
	          {
		         if(ss_a[cnt] != ss_b[cnt])
		      {	
			       break;
		      }
			  
	          }
				
              if(cnt!=SABER_KEYBYTES)
			  {
				  sk_hat[i][k]=8192-2;
				  
			  }
			  
			  else
			  {			  
				
				sk_hat[i][k]=8192-3;
				    
			  }
			  
			  
			  
              				
				  
				  
			  }
			  
			  
			  
			  
			  }
		 
		  
		      }
		 
		      else
		     {
			 
			 if(k==0){res[i][k]=3;}
			 else {res[i][SABER_N-k]=1024-3;}
			POLVECp2BS(ct, res);
			 
			
			 vprime[0]=16;
			POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
			  
			  //Key-Decapsulation call; input: sk, c; output: shared-secret ss_b;	
		     // It plays a role of Oracle on launching key mismatch attack
	          crypto_kem_dec(ss_b, ct, sk);
                 query++;	          
 
	          for(cnt=0; cnt<SABER_KEYBYTES; cnt++)
	          {
		         if(ss_a[cnt] != ss_b[cnt])
		      {	
			       break;
		      }
			  
	          }
			  
			  if(cnt==SABER_KEYBYTES)
			  {
				  sk_hat[i][k]=1;
			  }
			  
			  else 
			  {
			 if(k==0){res[i][k]=7;}
			 else {res[i][SABER_N-k]=1024-7;}
			 POLVECp2BS(ct, res); 
			 
			
			 vprime[0]=17;
			POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
			   
			   	
	          crypto_kem_dec(ss_b, ct, sk);
	         query++;

	          for(cnt=0; cnt<SABER_KEYBYTES; cnt++)
	          {
		         if(ss_a[cnt] != ss_b[cnt])
		      {	
			       break;
		      }
			  
	          }
				
               if(cnt==SABER_KEYBYTES)
			  {
				  sk_hat[i][k]=2;
			  }
			  
			 
			  else
			  {
			
              		 sk_hat[i][k]=3;		
				  
				  
			  }
			  
			  
			  
			  
			  }
			  
		     }
	

	 
			
	    }

	    }

 


   for(i=0;i<SABER_L;i++)
   {
		for(j=0;j<SABER_N;j++)
		{
                        if(sksv[i][j]!=sk_hat[i][j])printf("sk[%d][%d]:%d sk_hat[%d][%d]:%d\n",i,j,sksv[i][j],i,j,sk_hat[i][j]);
		}
   }
  	return query;
}



int main()
{
    // calculate the average time and average queries of 10000 times  
	struct timeval tv1,tv2;
       int count,query=0;
    gettimeofday(&tv1,NULL);
    srand((unsigned) time(NULL));
    for(count=0;count<10000;count++)
{ 
query+=test_pke_cpa();
}
	gettimeofday(&tv2,NULL);
    printf("total time:%.4fs\n",((double)(tv2.tv_sec-tv1.tv_sec)*1000+(double)(tv2.tv_usec-tv1.tv_usec)/1000)/1000);
   printf("total_average time:%.4fs\n",(((double)(tv2.tv_sec-tv1.tv_sec)*1000+(double)(tv2.tv_usec-tv1.tv_usec)/1000)/1000)/10000);
  printf("total_average queries:%.4f\n",(double)(query/10000.0));
	return 0;
}
