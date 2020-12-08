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
	
 int i,k,cnt,k2,kk;


   
    	for (i=0; i<48; i++)
        	entropy_input[i] = i;
     
              randombytes_init(entropy_input, NULL, 256);




	    //Generation of secret key sk and public key pk pair
	    crypto_kem_keypair(pk, sk);
        BS2POLVECq(sk, sksv); //sksv is the secret-key
	     
		  //recover -5<=sk[i]<=-2 && 2<=sk[i]<=5
		 memset(ss_a,0,sizeof(ss_a));
	     ss_a[0]=1;
		 
		 for(i=0;i<SABER_L;i++)
		{

		 memset(vprime,0,sizeof(vprime));			
		 for(k=0;k<SABER_N;k++)
	     {
			 memset(res,0,sizeof(res));
			 if(k==0){res[i][k]=35;}
			 else {res[i][SABER_N-k]=1024-35;}
			 
			 POLVECp2BS(ct, res);
			
			 vprime[0]=1;
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
		    
			 if(k==0){res[i][k]=34;}
			 else {res[i][SABER_N-k]=1024-34;}
			 POLVECp2BS(ct, res); 
			 
			
			 vprime[0]=1;
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
			 if(k==0){res[i][k]=22;}
			 else {res[i][SABER_N-k]=1024-22;}
			 POLVECp2BS(ct, res);
			 
			
			 vprime[0]=1;
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
				  sk_hat[i][k]=8192-3;
			  }
			  
			  else
			  {
				  if(k==0){res[i][k]=17;}
			      else {res[i][SABER_N-k]=1024-17;}
			     POLVECp2BS(ct, res); 
			 
			
			 vprime[0]=1;
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
				
              if(cnt!=SABER_KEYBYTES)
			  {
				  sk_hat[i][k]=8192-4;
				  
			  }
			  
			  else
			  {			  
				
				sk_hat[i][k]=8192-5;
				    
			  }
			  
			  
			  
              				
				  
				  
			  }
			  
			  
			  
			  
			  }
		 
		  
		      }
		 
		      else
		     {
				 
			 
			 if(k==0){res[i][k]=30;}
			 else {res[i][SABER_N-k]=1024-30;}
			POLVECp2BS(ct, res);
			 
			
			 vprime[0]=2;
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
				  sk_hat[i][k]=6;
			  }
			  
			  else 
			  {
			 if(k==0){res[i][k]=29;}
			 else {res[i][SABER_N-k]=1024-29;}
			 POLVECp2BS(ct, res); 
			 
			
			 vprime[0]=2;
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
			 if(k==0){res[i][k]=19;}
			 else {res[i][SABER_N-k]=1024-19;}
			 POLVECp2BS(ct, res); 
			 
			
			 vprime[0]=2;
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
				  sk_hat[i][k]=3;
			  }
			  
			  else
			  {
		     if(k==0){res[i][k]=14;}
			 else {res[i][SABER_N-k]=1024-14;}
			 POLVECp2BS(ct, res); 
			 
			
			 vprime[0]=2;
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
				  sk_hat[i][k]=4;

			  } 
			  
			  else
			  {  
			    sk_hat[i][k]=5;
			  
			  } 
				  
			  }
			  		
				  
				  
			  }
			  
			  
			  
			  
			  }
			  
		     }
	

	 
			
	     }

	    }
		
		
	   //recover -1<=sk[i]<=1
		 memset(ss_a,0,sizeof(ss_a));
	     ss_a[0]=1;		 
		 for(i=0;i<SABER_L;i++)
		{		
		 for(k=0;k<SABER_N;k++)
	     {
			
			if(sk_hat[i][k]==6)
			{
			  memset(vprime,0,sizeof(vprime));
			  memset(res,0,sizeof(res));
			 if(k==0){res[i][k]=60;}
			 else {res[i][SABER_N-k]=1024-60;}
			 
			 POLVECp2BS(ct, res);
			
			 vprime[0]=2;
                       
			 for(kk=k;kk<SABER_N;kk++)
		         {
				if((sk_hat[i][kk]<=8188)&&(sk_hat[i][kk]>=8187))
				{
  				   vprime[kk-k]=4;
				}
			 }
			 
			 for(k2=0;k2<k;k2++)
			 {
                                 if((sk_hat[i][k2]<=5)&&(sk_hat[i][k2]>=4))
                                  {
                                     vprime[kk-k+k2]=4; 
                                  }
			 }

			 
                    
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
			  
			 
			  if(cnt!=SABER_KEYBYTES)
			  {
				sk_hat[i][k]=1;
			  }
			  
			  else
			  {
			 memset(vprime,0,sizeof(vprime));
			  memset(res,0,sizeof(res));
			 if(k==0){res[i][k]=69;}
			 else {res[i][SABER_N-k]=1024-69;}
			 
			 POLVECp2BS(ct, res);
			
			 vprime[0]=1;
		
			  for(kk=k;kk<SABER_N;kk++)
		     {
				if((sk_hat[i][kk]==5)||((sk_hat[i][kk]<=8189)&&(sk_hat[i][kk]>=8187)))
				{ vprime[kk-k]=4;
			    }
			 }
			 
			 for(k2=0;k2<k;k2++)
			 {
				  if((sk_hat[i][k2]==8187)||((sk_hat[i][k2]<=5)&&(sk_hat[i][k2]>=3)))
				 {
				  vprime[kk-k+k2]=4;
				 }
			 }
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
				sk_hat[i][k]=8192-1;
			  }
			  else
			  {
			    sk_hat[i][k]=0;

           		  }
				  
			  }
				
		    }
		 
			
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
