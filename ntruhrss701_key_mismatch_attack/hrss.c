#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "rng.h"
#include "api.h"
#include "params.h"
#include "poly.h"
#include <sys/time.h>

int test_pke_cpa(int succe[1]);

int test_pke_cpa(int succe[1])
{
	//key mismatch attack on NTRU-HRSS
   // parameters:  ct: c
   //              ss: message
   //	        query: count the total queries
   
    unsigned char       seed[48];
    unsigned char       entropy_input[48];
    unsigned char       ct[CRYPTO_CIPHERTEXTBYTES];
	poly s1,s2,ghat,fhat;
	poly *ss;
	poly *ss1,*g_hat,*f_hat;
	ss=&s1;
	ss1=&s2;
	g_hat=&ghat;
	f_hat=&fhat;
    int                 done;
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];//secret key of the Alice
    int ret_val;
    int j,num,rj,rj0[2],flag[2],j0,sm=0,k,leng[1],query=0;
    int g[701],g_sk[3]={-1,0,1},G_sk[5],G[701],target[10],G_real[701],num1[1]={0},num2[1]={0},same[701],num_same=0;
    
    for (int i=0; i<48; i++)
        entropy_input[i] = i;

    randombytes_init(entropy_input, NULL, 256);
    for (int i=0; i<100; i++) 
	{
        randombytes(seed, 48);
    }
	
	for(int i=0;i<701;i++)
	{
		same[i]=-3;
        g[i]=-2;
        G[i]=-3;
	}


        
        randombytes_init(seed, NULL, 256);

        // Generate the public/private keypair
        if ( (ret_val = crypto_kem_keypair(pk, sk,G_real,leng)) != 0) //sk is the secret-key
		{
            printf("crypto_kem_keypair returned <%d>\n", ret_val);
            return 0;
        }


//find the longest chain of (-2,2,-2,2,-2,2..) 
      for(j=2;j<30;j++)    
    {
        num=0;
        if(j<10) rj=(int)(8191.0/(2.0*3.0*8.0*j)+1);
        else rj=(int)(8191.0/(2.0*3.0*6.0*j)+1);
		
        if ( (ret_val = crypto_kem_enc(ct, ss, pk,j,rj))!= 0) 
        {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            return 0;
        }
                
                
                

             /*Key-Decapsulation call; input:c,sk; output: shared-secret ss1;	
	      It plays a role of Oracle on launching key mismatch attack*/
        if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) 
		{
            printf("crypto_kem_dec returned <%d>\n", ret_val);
            return 0;
        }
         
                query++;
                
                for (int cnt=0;cnt<NTRU_N;cnt++)
                {
                        if(ss->coeffs[cnt]==ss1->coeffs[cnt])
                        {
                                num++;
                        }
                }
                if(num==NTRU_N)break;
    }


   for(j0=0;j0<j-1;j0++)
 {
  if((j0%2)==0){G[j0]=-2;g[j0]=1;}
  else {G[j0]=2;g[j0]=-1;}
 }



  for(int cc=0;cc<701;cc++)
 {
     same[cc]=-3;
 }

k=j;
num2[0]+=j-1;

//find the remaining coefficients of G[i+t](t=0,...NTRU_N-k)
 for(j0=0;j0<NTRU_N-k+1;j0++)
{
        G_sk[0]=g[j-2+j0]-g_sk[0];

        G_sk[1]=0;


        G_sk[2]=0;

     //calculate +-2's weight
     
    //result: G_sk[1]: unit value of parameter r
    //        G_sk[3]: weight

       G_sk[2]=2*4*(num2[0]+1)+num1[0];
       G_sk[1]=(int)(8191/(2*3*G_sk[2])+1);

       G_sk[2]=G_sk[1]*3*(2*4*num2[0]+num1[0]);

       G_sk[3]=(int)((4095-G_sk[2])/(G_sk[1]*3)+1);

       if((G_sk[2]>=4096)||(G_sk[3]<4*2))
     {
       G_sk[2]=2*3*(num2[0]+1)+num1[0];
       G_sk[1]=(int)(8191/(2*3*G_sk[2])+1);

       G_sk[2]=G_sk[1]*3*(2*3*num2[0]+num1[0]);

       G_sk[3]=(int)((4095-G_sk[2])/(G_sk[1]*3)+1);

       if((G_sk[2]>=4096)||(G_sk[3]<3*2))
      {
       G_sk[2]=2*2*(num2[0]+1)+num1[0];
       G_sk[1]=(int)(8191/(2*3*G_sk[2])+1);

       G_sk[2]=G_sk[1]*3*(2*2*num2[0]+num1[0]);

       G_sk[3]=(int)((4095-G_sk[2])/(G_sk[1]*3)+1);

         if((G_sk[2]>=4096)||(G_sk[3]<2*2))
        {
         G_sk[2]=2*(num2[0]+1)+num1[0];
         G_sk[1]=(int)(8191/(2*3*G_sk[2])+1);
         G_sk[3]=1;
        }
         else
        {
         G_sk[3]=2; 
        }
      
      }

       else
      {
       G_sk[3]=3;
      }


    }

    else
   { 
     G_sk[3]=4;
   }




//find (2,0) (0,2) (0,-2) (-2,0)


	
//(-2,0) (0,-2) 
  if(G_sk[0]==0)
  {	
       rj0[0]=G_sk[1];
       rj0[1]=G_sk[1];
	   num=0;

        if ( (ret_val = crypto_kem_enc1(ct, ss, pk,k,j0,rj0[0],rj0[1],G,G_sk[3],same))!= 0)
                {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            return 0;
        }




       
              /*Key-Decapsulation call; input:c,sk; output: shared-secret ss1;	
	      It plays a role of Oracle on launching key mismatch attack*/
        if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) 
		{
            printf("crypto_kem_dec returned <%d>\n", ret_val);
            return 0;
        }

                query++;

                for (int cnt=0;cnt<NTRU_N;cnt++)
                {
                        if(ss->coeffs[cnt]==ss1->coeffs[cnt])
                        {
                                num++;
                        }
                }
                if(num==NTRU_N){flag[0]=1;}
                else {flag[0]=0;}
				
				
	
      rj0[0]=G_sk[1];
      rj0[1]=G_sk[3]*G_sk[1];
      num=0;

        if ( (ret_val = crypto_kem_enc1(ct, ss, pk,k,j0,rj0[0],rj0[1],G,G_sk[3],same))!= 0)
       {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            return 0;
       }
		
              /*Key-Decapsulation call; input:c,sk; output: shared-secret ss1;	
	      It plays a role of Oracle on launching key mismatch attack*/
         if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) 
	    {
            printf("crypto_kem_dec returned <%d>\n", ret_val);
            return 0;
        }
                query++;

                for (int cnt=0;cnt<NTRU_N;cnt++)
                {
                        if(ss->coeffs[cnt]==ss1->coeffs[cnt])
                        {
                                num++;
                        }
                }
                if(num==NTRU_N){flag[1]=1;}
                else {flag[1]=0;}





        if(flag[0]==0&&flag[1]==1)
        {
				 
            g[j0+k-1]=g_sk[2];
	        g[j0+k]=g_sk[2];
				
            G[j0+k-1]=-2;
            if((j0+k-1)<=14){num2[0]++;}
	        G[j0+k]=0;
		    j0++;                
		    continue;               
        }
        else if(flag[0]==1&&flag[1]==0)
        { 
				 
            g[j0+k-1]=g_sk[0];
		    g[j0+k]=g_sk[2];
				
            G[j0+k-1]=0;
		    G[j0+k]=-2;
            if((j0+k)<=14){num2[0]++;}
            j0++;
	        continue;
     }
  }
  
  //(2,0) (0,2) 
  else if(G_sk[0]==2)
  {	  
        rj0[0]=G_sk[1];
        rj0[1]=8192-G_sk[1];
	    num=0;

        if ( (ret_val = crypto_kem_enc1(ct, ss, pk,k,j0,rj0[0],rj0[1],G,G_sk[3],same))!= 0)
       {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            return 0;
       }




     
              /*Key-Decapsulation call; input:c,sk; output: shared-secret ss1;	
	      It plays a role of Oracle on launching key mismatch attack*/
        if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) 
		{
            printf("crypto_kem_dec returned <%d>\n", ret_val);
            return 0;
        }

                query++;


                for (int cnt=0;cnt<NTRU_N;cnt++)
                {
                        if(ss->coeffs[cnt]==ss1->coeffs[cnt])
                        {
                                num++;
                        }
                }
                if(num==NTRU_N){flag[0]=1;}
                else {flag[0]=0;}
				
				
	

        rj0[0]=G_sk[1];
        rj0[1]=8192-G_sk[3]*G_sk[1];
        num=0;

        if ( (ret_val = crypto_kem_enc1(ct, ss, pk,k,j0,rj0[0],rj0[1],G,G_sk[3],same))!= 0)
        {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            return 0;
        }
		
		
       //Key-Decapsulation call; input:c,sk; output: shared-secret ss1;	
		     // It plays a role of Oracle on launching key mismatch attack
        if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) 
		{
            printf("crypto_kem_dec returned <%d>\n", ret_val);
            return 0;
        }
        query++;

                for (int cnt=0;cnt<NTRU_N;cnt++)
                {
                        if(ss->coeffs[cnt]==ss1->coeffs[cnt])
                        {
                                num++;
                        }
                }
                if(num==NTRU_N){flag[1]=1;}
                else {flag[1]=0;}





        if(flag[0]==0&&flag[1]==1)
        {
				 
                g[j0+k-1]=g_sk[0];
		        g[j0+k]=g_sk[0];
				
                G[j0+k-1]=2;
		        G[j0+k]=0;
                if((j0+k-1)<=14){num2[0]++;}
                j0++;
		        continue;
                
        }
        else if(flag[0]==1&&flag[1]==0)
        {   
                g[j0+k-1]=g_sk[2];
		        g[j0+k]=g_sk[0];
				
                G[j0+k-1]=0;
		        G[j0+k]=2;
                if((j0+k)<=14){num2[0]++;}
                j0++;
		        continue;
        }
  }
	


      //calculate +-2's weight in (-2,-1,0) or (2,1,0)

    //result: G_sk[1]: unit value of parameter r1
    //        G_sk[4]: unit value of parameter r2
    //        G_sk[3]: weight

       G_sk[2]=2*4*num2[0]+num1[0]+1;
       G_sk[1]=(int)(8191/(2*3*G_sk[2])+1);

       G_sk[2]=G_sk[1]*3*(2*4*num2[0]+num1[0]);

       G_sk[3]=2*4*num2[0]+num1[0]+2;
       G_sk[4]=(int)(8191/(2*3*G_sk[3])+1);
      
       G_sk[3]=G_sk[4]*3*(2*4*num2[0]+num1[0]);

       if((G_sk[2]>=4096)||(G_sk[3]>=4096)||(G_sk[1]==G_sk[4]))
     {
       
       G_sk[2]=2*3*num2[0]+num1[0]+1;
       G_sk[1]=(int)(8191/(2*3*G_sk[2])+1);

       G_sk[2]=G_sk[1]*3*(2*3*num2[0]+num1[0]);

       G_sk[3]=2*3*num2[0]+num1[0]+2;
       G_sk[4]=(int)(8191/(2*3*G_sk[3])+1);

       G_sk[3]=G_sk[4]*3*(2*3*num2[0]+num1[0]);

       if((G_sk[2]>=4096)||(G_sk[3]>=4096)||(G_sk[1]==G_sk[4]))
      {
       G_sk[2]=2*2*num2[0]+num1[0]+1;
       G_sk[1]=(int)(8191/(2*3*G_sk[2])+1);

       G_sk[2]=G_sk[1]*3*(2*2*num2[0]+num1[0]);

       G_sk[3]=2*2*num2[0]+num1[0]+2;
       G_sk[4]=(int)(8191/(2*3*G_sk[3])+1);

       G_sk[3]=G_sk[4]*3*(2*2*num2[0]+num1[0]);

         if((G_sk[2]>=4096)||(G_sk[3]>=4096)||(G_sk[1]==G_sk[4]))
        {
          G_sk[2]=2*1*num2[0]+num1[0]+1;
          G_sk[1]=(int)(8191/(2*3*G_sk[2])+1);

          G_sk[3]=2*1*num2[0]+num1[0]+2;
          G_sk[4]=(int)(8191/(2*3*G_sk[3])+1);
              
          G_sk[3]=1;
        }
         else
        {
         G_sk[3]=2;
        }

      }

       else
      {
       G_sk[3]=3;
      }


    }

    else
   {
    G_sk[3]=4;
   }    
      

   //(-2,-1,0) 
       if(G_sk[0]==0)
   {
         rj0[0]=G_sk[1];
         rj0[1]=G_sk[1];
         num=0;

        if ( (ret_val = crypto_kem_enc0(ct, ss, pk,k,j0,rj0[0],rj0[1],G,G_sk[3],same))!= 0)
                {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            return 0;
        }




        
       //Key-Decapsulation call; input:c,sk; output: shared-secret ss1;	
		     // It plays a role of Oracle on launching key mismatch attack
        if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) {
            printf("crypto_kem_dec returned <%d>\n", ret_val);
            return 0;
        }

                query++;

                for (int cnt=0;cnt<NTRU_N;cnt++)
                {
                        if(ss->coeffs[cnt]==ss1->coeffs[cnt])
                        {
                                num++;
                        }
                }
                if(num==NTRU_N){flag[0]=1;}
                else {flag[0]=0;}

            rj0[0]=G_sk[4];
            rj0[1]=G_sk[4];
            num=0;

        if ( (ret_val = crypto_kem_enc0(ct, ss, pk,k,j0,rj0[0],rj0[1],G,G_sk[3],same))!= 0)
        {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            return 0;
        }
		
		
       /*Key-Decapsulation call; input:c,sk; output: shared-secret ss1;	
	      It plays a role of Oracle on launching key mismatch attack*/
        if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) 
		{
            printf("crypto_kem_dec returned <%d>\n", ret_val);
            return 0;
        }
                query++;

                for (int cnt=0;cnt<NTRU_N;cnt++)
                {
                        if(ss->coeffs[cnt]==ss1->coeffs[cnt])
                        {
                                num++;
                        }
                }
                if(num==NTRU_N){flag[1]=1;}
                else {flag[1]=0;}





        if(flag[0]==0&&flag[1]==1)
        {
                g[j0+k-1]=g_sk[1];
                G[j0+k-1]=-1;
               if((j0+k-1)<=14){num1[0]++;}
                
        }
        else if(flag[0]==0&&flag[1]==0)
        {
                g[j0+k-1]=g_sk[2];
                G[j0+k-1]=-2;
               if((j0+k-1)<=14){num2[0]++;}
        }

        else if(flag[0]==1&&flag[1]==1)
        {
                g[j0+k-1]=g_sk[0];
                G[j0+k-1]=0;
        }

   }

  //(-1,0,1)
   else if(G_sk[0]==1)
{

     //calculate +-2's weight in (-1,0,1)

    //result: G_sk[1]: unit value of parameter r
    //        G_sk[3]: weight

       G_sk[2]=2*4*num2[0]+num1[0]+1;
       G_sk[1]=(int)(8191/(2*3*G_sk[2])+1);

       G_sk[2]=G_sk[1]*3*(2*4*num2[0]+num1[0]);


       if(G_sk[2]>=4096)
     {
        G_sk[2]=2*3*num2[0]+num1[0]+1;
        G_sk[1]=(int)(8191/(2*3*G_sk[2])+1);

        G_sk[2]=G_sk[1]*3*(2*3*num2[0]+num1[0]);

       if(G_sk[2]>=4096)
      {
        G_sk[2]=2*2*num2[0]+num1[0]+1;
        G_sk[1]=(int)(8191/(2*3*G_sk[2])+1);

        G_sk[2]=G_sk[1]*3*(2*2*num2[0]+num1[0]);

         if(G_sk[2]>=4096)
        {
          G_sk[2]=2*1*num2[0]+num1[0]+1;
          G_sk[1]=(int)(8191/(2*3*G_sk[2])+1);
          
          G_sk[3]=1;
        }
         else
        {
         G_sk[3]=2;
        }

      }

       else
      {
       G_sk[3]=3;
      }


    }

    else
   {
     G_sk[3]=4;
   }













         rj0[0]=G_sk[1];
         rj0[1]=G_sk[1];
         num=0;

        if ( (ret_val = crypto_kem_enc0(ct, ss, pk,k,j0,rj0[0],rj0[1],G,G_sk[3],same))!= 0)
        {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            return 0;
        }

       /*Key-Decapsulation call; input:c,sk; output: shared-secret ss1;	
	      It plays a role of Oracle on launching key mismatch attack*/     
        if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) 
		{
            printf("crypto_kem_dec returned <%d>\n", ret_val);
            return 0;
        }

                query++;

                for (int cnt=0;cnt<NTRU_N;cnt++)
                {
                        if(ss->coeffs[cnt]==ss1->coeffs[cnt])
                        {
                                num++;
                        }
                }
                if(num==NTRU_N){flag[0]=1;}
                else {flag[0]=0;}
            rj0[0]=G_sk[1];
            rj0[1]=8192-G_sk[1];
            num=0;

        if ( (ret_val = crypto_kem_enc0(ct, ss, pk,k,j0,rj0[0],rj0[1],G,G_sk[3],same))!= 0)
        {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            return 0;
        }
         
       /*Key-Decapsulation call; input:c,sk; output: shared-secret ss1;	
	      It plays a role of Oracle on launching key mismatch attack*/		 
	    if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) 
		{
            printf("crypto_kem_dec returned <%d>\n", ret_val);
                     return 0;
        }
                query++;
                for (int cnt=0;cnt<NTRU_N;cnt++)
                {
                        if(ss->coeffs[cnt]==ss1->coeffs[cnt])
                        {
                                num++;
                        }
                }
                if(num==NTRU_N){flag[1]=1;}
                else {flag[1]=0;}





        if(flag[0]==0&&flag[1]==1)
        {
                g[j0+k-1]=g_sk[2];
                G[j0+k-1]=-1;
               if((j0+k-1)<=14){num1[0]++;}
        }
        else if(flag[0]==1&&flag[1]==0)
        {
                
                g[j0+k-1]=g_sk[0];
                G[j0+k-1]=1;
                if((j0+k-1)<=14){num1[0]++;}
        }

        else if(flag[0]==1&&flag[1]==1)
        {
                g[j0+k-1]=g_sk[1];
                G[j0+k-1]=0;
        }
        else if(flag[0]==0&&flag[1]==0)
        {
            g[j0+k-1]=g_sk[2];
            G[j0+k-1]=-1;
           if((j0+k-1)<=14){num1[0]++;}
           else 
           {
             same[num_same]=j0;
             num_same++;
             num1[0]++;
           }
       }
  }

//(2,1,0)
  else if(G_sk[0]==2)
{
         rj0[0]=G_sk[1];
         rj0[1]=8192-G_sk[1];
         num=0;

        if ( (ret_val = crypto_kem_enc0(ct, ss, pk,k,j0,rj0[0],rj0[1],G,G_sk[3],same))!= 0)
        {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            return 0;
        }





        if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) 
		{
            printf("crypto_kem_dec returned <%d>\n", ret_val);
            return 0;
        }

                query++;


                for (int cnt=0;cnt<NTRU_N;cnt++)
                {
                        if(ss->coeffs[cnt]==ss1->coeffs[cnt])
                        {
                                num++;
                        }
                }
                if(num==NTRU_N){flag[0]=1;}
                else {flag[0]=0;}

            rj0[0]=G_sk[4];
            rj0[1]=8192-G_sk[4];
            num=0;

        if ( (ret_val = crypto_kem_enc0(ct, ss, pk,k,j0,rj0[0],rj0[1],G,G_sk[3],same))!= 0)
       {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            return 0;
       }
		 
	       /*Key-Decapsulation call; input:c,sk; output: shared-secret ss1;	
	      It plays a role of Oracle on launching key mismatch attack*/	
        if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) 
	   {
            printf("crypto_kem_dec returned <%d>\n", ret_val);
                     return 0;
       }
          query++;

                for (int cnt=0;cnt<NTRU_N;cnt++)
                {
                        if(ss->coeffs[cnt]==ss1->coeffs[cnt])
                        {
                                num++;
                        }
                }
                if(num==NTRU_N){flag[1]=1;}
                else {flag[1]=0;}





        if(flag[0]==0&&flag[1]==1)
        {
                g[j0+k-1]=g_sk[1];
                G[j0+k-1]=1;
                if((j0+k-1)<=14){num1[0]++;}
        }
        else if(flag[0]==0&&flag[1]==0)
        {
                g[j0+k-1]=g_sk[0];
                G[j0+k-1]=2;
                if((j0+k-1)<=14){num2[0]++;}
        }

        else if(flag[0]==1&&flag[1]==1)
        {
                g[j0+k-1]=g_sk[2];
                G[j0+k-1]=0;
        } 

}
   
}



for(j0=0;j0<NTRU_N;j0++)
{
  G[j0]=(G[j0]+8192)%8192;
}

int cntt=0;


int recording[4]={-1,-1,-1,-1};
for(int i=0;i<NTRU_N-9;++i)
{
  if(G_real[i]==G[0])
{
  if(G_real[i+1]==G[1])
{
 if(G_real[i+2]==G[2])
{
  if(G_real[i+3]==G[3])
{
 if(G_real[i+4]==G[4])
{
 if(G_real[i+5]==G[5])
{

if(G_real[i+6]==G[6])
{

if(G_real[i+7]==G[7])
{

if(G_real[i+8]==G[8])
{
if(G_real[i+9]==G[9])
{
recording[0]=i;
cntt++;
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


if(G_real[i]==G[9])
{
  if(G_real[i+1]==G[8])
{
 if(G_real[i+2]==G[7])
{
  if(G_real[i+3]==G[6])
{
 if(G_real[i+4]==G[5])
{
 if(G_real[i+5]==G[4])
{

if(G_real[i+6]==G[3])
{

if(G_real[i+7]==G[2])
{

if(G_real[i+8]==G[1])
{
if(G_real[i+9]==G[0])
{
recording[1]=i+9;
cntt++;
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


if(G_real[i]==((8192-G[0])%8192))
{
  if(G_real[i+1]==((8192-G[1])%8192))
{
 if(G_real[i+2]==((8192-G[2])%8192))
{
  if(G_real[i+3]==((8192-G[3])%8192))
{
 if(G_real[i+4]==((8192-G[4])%8192))
{
 if(G_real[i+5]==((8192-G[5])%8192))
{

if(G_real[i+6]==((8192-G[6])%8192))
{

if(G_real[i+7]==((8192-G[7])%8192))
{

if(G_real[i+8]==((8192-G[8])%8192))
{
if(G_real[i+9]==((8192-G[9])%8192))
{
recording[2]=i;
cntt++;
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

 if(G_real[i]==((8192-G[9])%8192))
{
  if(G_real[i+1]==((8192-G[8])%8192))
{
 if(G_real[i+2]==((8192-G[7])%8192))
{
  if(G_real[i+3]==((8192-G[6])%8192))
{
 if(G_real[i+4]==((8192-G[5])%8192))
{
 if(G_real[i+5]==((8192-G[4])%8192))
{

if(G_real[i+6]==((8192-G[3])%8192))
{

if(G_real[i+7]==((8192-G[2])%8192))
{

if(G_real[i+8]==((8192-G[1])%8192))
{
if(G_real[i+9]==((8192-G[0])%8192))
{
recording[3]=i+9;
cntt++;
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



//verify whether the found G is true or not 
    if(recording[0]!=-1)
 { 
   for(j=recording[0];j<NTRU_N;j++)
  {
    if(G_real[j]!=G[j-recording[0]])break;  
  }

  if(j==NTRU_N)
 {
    for(j=0;j<recording[0];j++)
   {
    if(G_real[j]!=G[NTRU_N-recording[0]+j])break;
   }
    if(j==recording[0])
    {
            succe[0]=1;
	}

 }

}


 if(recording[1]!=-1)
{
  for(j=recording[1];j>=0;j--)
 {
    if(G_real[j]!=G[recording[1]-j])break;
 }

 if(j==-1)
 {
   for(j=recording[1]+1;j<NTRU_N;j++)
 {
    if(G_real[j]!=G[NTRU_N+recording[1]-j])break;
 }
 if(j==NTRU_N)
 {
         succe[0]=1;
 }
}

}

 if(recording[2]!=-1)
{
  for(j=recording[2];j<NTRU_N;j++)
  {
    if(G_real[j]!=((8192-G[j-recording[2]])%8192))break;
  }

  if(j==NTRU_N)
 {
    for(j=0;j<recording[2];j++)
   {
    if(G_real[j]!=((8192-G[NTRU_N-recording[2]+j])%8192))break;
   }
    if(j==recording[2])
    {
            succe[0]=1;
    }

 }
}


 if(recording[3]!=-1)
{

for(j=recording[3];j>=0;j--)
 {
    if(G_real[j]!=((8192-G[recording[3]-j])%8192))break;
 }

 if(j==-1)
{
   for(j=recording[3]+1;j<NTRU_N;j++)
 {
    if(G_real[j]!=((8192-G[NTRU_N+recording[3]-j])%8192))break;
 }
 if(j==NTRU_N)
 {
  succe[0]=1;
 }
       

}

}
	
	return query;


}

// calculate the average time, the success rate and average queries on recovering the secret-key successfully of 10000 times
int main(int argc, char *argv[])
{
   printf("argc:%d\n",argc);
    struct timeval tv1,tv2;
    int count,query=0,succe[1],tmp,cnt=0;
    gettimeofday(&tv1,NULL);
    srand(argc);
    for(count=0;count<10000;count++)
   { 
     succe[0]=0;
     tmp=test_pke_cpa(succe);
     if(succe[0]==1)
    {   
     query+=tmp;
     cnt++;
    } 
   }
     gettimeofday(&tv2,NULL);
     printf("total time:%.4fs\n",((double)(tv2.tv_sec-tv1.tv_sec)*1000+(double)(tv2.tv_usec-tv1.tv_usec)/1000)/1000);
     printf("total_average time:%.4fs\n",(((double)(tv2.tv_sec-tv1.tv_sec)*1000+(double)(tv2.tv_usec-tv1.tv_usec)/1000)/1000)/10000.0);
     printf("total_average accuracy:%.4f\n",(double)(cnt/10000.0));
     printf("total_average queries:%.4f\n",(double)(query*1.0/cnt));
	return 0;
}

