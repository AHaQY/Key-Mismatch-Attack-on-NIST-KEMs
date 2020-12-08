/********************************************************************************************
* Frodokem: Learning with Errors Public-Key
*
* Abstract: Public-Key Encryption (kem) based on Frodo
*********************************************************************************************/

#include <string.h>
#include <stdio.h>
#include "sha3/fips202.h"
#include "random/random.h"


int crypto_kem_keypair(unsigned char* pk, unsigned char* sk)
{ // Frodopke's key generation
  // Outputs: public key pk (               BYTES_SEED_A + (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8 bytes)
  //          secret key sk (2*PARAMS_N*PARAMS_NBAR bytes)
    uint8_t *pk_seedA = &pk[0];
    uint8_t *pk_b = &pk[BYTES_SEED_A];
    uint8_t *sk_S = &sk[0];
    
    uint16_t B[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t S[2*PARAMS_N*PARAMS_NBAR] = {0};               // contains secret data
    uint16_t *E = (uint16_t *)&S[PARAMS_N*PARAMS_NBAR];     // contains secret data
    uint8_t randomness[BYTES_SEED_A+CRYPTO_BYTES];      // contains secret data via randomness_seedA and randomness_seedSE
    uint8_t *randomness_seedA = &randomness[0];                 // contains secret data
    uint8_t *randomness_seedSE = &randomness[BYTES_SEED_A]; // contains secret data
    uint8_t shake_input_seedSE[1 + CRYPTO_BYTES];

    // Generate the secret value s, the seed for S and E, and the seed for the seed for A. Add seed_A to the public key
    randombytes(randomness, BYTES_SEED_A+CRYPTO_BYTES);

    // Generate S and E, and compute B = A*S + E. Generate A on-the-fly
    shake_input_seedSE[0] = 0x5F;
    memcpy(&shake_input_seedSE[1], randomness_seedSE, CRYPTO_BYTES);
    shake((uint8_t*)S, 2*PARAMS_N*PARAMS_NBAR*sizeof(uint16_t), shake_input_seedSE, 1 + CRYPTO_BYTES);
    for (size_t i = 0; i < 2 * PARAMS_N * PARAMS_NBAR; i++) {
        S[i] = LE_TO_UINT16(S[i]);
    }
    frodo_sample_n(S, PARAMS_N*PARAMS_NBAR);
    frodo_sample_n(E, PARAMS_N*PARAMS_NBAR);
    frodo_mul_add_as_plus_e(B, S, E, randomness_seedA);
    
    // Add seedA,B to the public key
    memcpy(pk_seedA, randomness_seedA, BYTES_SEED_A);
    frodo_pack(pk_b, CRYPTO_PUBLICKEYBYTES - BYTES_SEED_A, B, PARAMS_N*PARAMS_NBAR, PARAMS_LOGQ);
    
    // Add S to the secret key
    for (size_t i = 0; i < PARAMS_N * PARAMS_NBAR; i++) {
        S[i] = UINT16_TO_LE(S[i]);
    }
    memcpy(sk_S, S, 2*PARAMS_N*PARAMS_NBAR);

    // Cleanup:
    clear_bytes((uint8_t *)S, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)E, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes(randomness, BYTES_SEED_A+CRYPTO_BYTES);
    clear_bytes(shake_input_seedSE, 1 + CRYPTO_BYTES);
    return 0;
}


int crypto_kem_enc(unsigned char *ct,unsigned char *mup,const unsigned char *pk)
{ // Frodopke's key encryption
    const uint8_t *pk_seedA = &pk[0];
    const uint8_t *pk_b = &pk[BYTES_SEED_A];
    uint8_t *ct_c1 = &ct[0];
    uint8_t *ct_c2 = &ct[(PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8];
    
    uint16_t B[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t V[PARAMS_NBAR*PARAMS_NBAR]= {0};                 // contains secret data
    uint16_t C[PARAMS_NBAR*PARAMS_NBAR] = {0};
    
    ALIGN_HEADER(32) uint16_t Bp[PARAMS_N*PARAMS_NBAR] ALIGN_FOOTER(32) = {0};
    ALIGN_HEADER(32) uint16_t Sp[(2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR] ALIGN_FOOTER(32) = {0};  // contains secret data
    uint16_t *Ep = (uint16_t *)&Sp[PARAMS_N*PARAMS_NBAR];     // contains secret data
    uint16_t *Epp = (uint16_t *)&Sp[2*PARAMS_N*PARAMS_NBAR];  // contains secret data
    
    uint8_t shake_input_seedSE[1 + CRYPTO_BYTES];             // contains secret data
    uint8_t seedSE[CRYPTO_BYTES]={0}; // contains secret data
    uint8_t *mu = &mup[0];                  // contains secret data
    //Generate message mu
    randombytes(mu, BYTES_MU);
    
    // Generate Sp and Ep, and compute Bp = Sp*A + Ep. Generate A on-the-fly
    randombytes(seedSE, CRYPTO_BYTES);
    shake_input_seedSE[0] = 0x96;
    memcpy(&shake_input_seedSE[1], seedSE, CRYPTO_BYTES);
    shake((uint8_t*)Sp, (2*PARAMS_N+PARAMS_NBAR)*PARAMS_NBAR*sizeof(uint16_t), shake_input_seedSE, 1 + CRYPTO_BYTES);
    for (size_t i = 0; i < (2 * PARAMS_N + PARAMS_NBAR) * PARAMS_NBAR; i++) {
        Sp[i] = LE_TO_UINT16(Sp[i]);
    }
    frodo_sample_n(Sp, PARAMS_N*PARAMS_NBAR);
    frodo_sample_n(Ep, PARAMS_N*PARAMS_NBAR);
    frodo_mul_add_sa_plus_e(Bp, Sp, Ep, pk_seedA);

    // Generate Epp, and compute V = Sp*B + Epp
    frodo_sample_n(Epp, PARAMS_NBAR*PARAMS_NBAR);
    frodo_unpack(B, PARAMS_N*PARAMS_NBAR, pk_b, CRYPTO_PUBLICKEYBYTES - BYTES_SEED_A, PARAMS_LOGQ);
    frodo_mul_add_sb_plus_e(V, B, Sp, Epp);

    // Encode mu, and compute C = V + enc(mu) (mod q)
    frodo_key_encode(C, (uint16_t*)mu);
    frodo_add(C, V, C);
    frodo_pack(ct_c1, (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8, Bp, PARAMS_N*PARAMS_NBAR, PARAMS_LOGQ);
    frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);


    // Cleanup:
    clear_bytes((uint8_t *)V, PARAMS_NBAR*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)Sp, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)Ep, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)Epp, PARAMS_NBAR*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes(shake_input_seedSE, 1 + CRYPTO_BYTES);
    return 0;
}


int crypto_kem_dec(unsigned char *mu,unsigned char *mup, const unsigned char *ct, const unsigned char *sk)
{ // Frodopke's key decryption
 //  It plays a role of Oracle on key mismatch attack  
//   Inputs:   ciphertext ct
//             message mu
//   outputs:  1 or 0
    uint16_t W[PARAMS_NBAR*PARAMS_NBAR] = {0};                // contains secret data
    uint8_t *muprime = &mup[0];                  // contains secret data
    uint16_t C1[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t C2[PARAMS_NBAR*PARAMS_NBAR] = {0};
    const uint8_t *ct_c1 = &ct[0];
    const uint8_t *ct_c2 = &ct[(PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8];
    const uint16_t *sk_S = (uint16_t *) &sk[0];
    // Compute W = C2- C1*S (mod q), and decode the randomness mu
    frodo_unpack(C1, PARAMS_N*PARAMS_NBAR, ct_c1, (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8, PARAMS_LOGQ);
    frodo_unpack(C2, PARAMS_NBAR*PARAMS_NBAR, ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, PARAMS_LOGQ); 
    frodo_mul_bs(W, C1, sk_S);
    frodo_sub(W,C2, W);
    frodo_key_decode((uint16_t*)muprime, W);

    // Cleanup:
    clear_bytes((uint8_t *)W, PARAMS_NBAR*PARAMS_NBAR*sizeof(uint16_t));
    if (memcmp(mu, mup, CRYPTO_BYTES) == 0){return 1;}
    return 0;
}

