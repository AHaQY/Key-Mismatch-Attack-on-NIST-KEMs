
//
//  PQCgenKAT_kem.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include "rng.h"
#include "api.h"

#define	MAX_MARKER_LEN		50
#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

int		FindMarker(FILE *infile, const char *marker);
int		ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
void	fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

/********** Attack *************/

/* the table about h and corresponding s
 * example  h = 9 corresponding s = 0   */
static int htable[5][2] = {{5, 0}, {6, 1}, {4, -1}, {7, 2}, {3, -2}};

/* check the h to get corresponding s */ 
static int checkh(int h) {
    for(int i = 0; i < 5; i++) {
        if(htable[i][0] == h)
            return htable[i][1];
    }
    return 99;      //fail check
}

static int kyber_Attack(int r) {


    /* random init */
    unsigned char       rand_seed[48];
    unsigned char       entropy_input[48];
    //srand(time(NULL));
    srand(r);
    for (int i=0; i<48; i++)
        entropy_input[i] = rand() % 48;
    randombytes_init(entropy_input, NULL, 256);


    /*pk sk ct*/
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    unsigned char       ct[CRYPTO_CIPHERTEXTBYTES];

    /* the s  recovered by adversary */
    signed char         recs[KYBER_K][KYBER_N] = { 0 };
    /* the polyvec form of true s */
    polyvec             skpoly = { { 0 } };
    /* the m set by adversary */
    unsigned char       m[KYBER_SYMBYTES]  = { 0 };
    m[0] = 0x1; // first coeff of m is 1

    /* get key pair */
    if (  crypto_kem_keypair(pk, sk, &skpoly) != 0 ) {
        printf("crypto_kem_keypair error\n");
        return KAT_CRYPTO_FAILURE;
    }

    
    int h ;   //parameter
    int query = 0;

/*  controlling the version of the attack , */
#define OPTIMIZATION        // uncomment this to get the version without optimization
#ifndef OPTIMIZATION
    /*  no optimization */
    /* loop h to recover s */
    for(int i = 0; i < KYBER_K; i++) {
        for(int k = 0; k < KYBER_N; k++) {
            for(h = 0; h < 16; h++) {
                kemenc_Attack(ct, m, pk, h, k, i); // choose appropriate ct
                query += 1;                        // count queries  
                if(oracle(ct, sk, m) == 1) {       // send ct to oracle 
                    //printf("%d ",h);
                    break;
                }
            }
            recs[i][k] = checkh(h);                // check the value of h to get s
        }
    }


#else
    /*  optimization */
    for(int i = 0; i < KYBER_K; i++) {
        for(int k = 0; k < KYBER_N; k++) {
            kemenc_Attack(ct, m, pk, 5, k, i);       // set h = 9
            if(oracle(ct, sk, m) == 1) {
                query += 1;
                kemenc_Attack(ct, m, pk, 4, k, i);  // set h = 8
                if(oracle(ct, sk, m) == 0) {
                    recs[i][k] = 0;
                    query += 1;
                }
                else {
                    query += 1;
                    kemenc_Attack(ct, m, pk, 3, k, i);
                    if(oracle(ct, sk, m) == 0) {
                        recs[i][k] = -1;
                        query += 1;
                    }
                    else {
                        recs[i][k] = -2;
                        query += 1;
                    }   
                }
            }
            else {
                query += 1;
                kemenc_Attack(ct, m, pk, 6, k, i);
                if(oracle(ct, sk, m) == 1) {
                    recs[i][k] = 1;
                    query += 1;
                }
                else {
                    recs[i][k] = 2;
                    query += 1; 
                }
            }
        }
    }
#endif
    /* check the recs recovere by adversary  ==  the true s */
    int checks = 0;
    for(int i = 0; i < KYBER_K; i++) {
        for(int j = 0; j < KYBER_N; j++) {
            if(recs[i][j] != skpoly.vec[i].coeffs[j]) {
                checks++;
                printf("error s in s[%d][%d] ", i, j);
            }
        }   
        // if(checks == 0){
        //     printf("right s[%d]\n", i);
        // }
    }
    /* print the queries */
    if(checks == 0)
        printf("fact queries: %d\n", query);
    else 
        printf("not correct\n");
    return query;
}


// need a rand seed from shell
int
main(int argc, char * argv[])
{

    if(argc == 1) {
        printf("need a number for random\n");
        return 0;
    }
    int rand = atoi(argv[1]);

    kyber_Attack(rand);     
    return 0;
   
}



