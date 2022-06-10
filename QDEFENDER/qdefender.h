/**
 * QDEFENDER - post-quantum algorithms as ..so lib
 *
 * HEAP mode to minimize the RAM allocation and allow all algorithms.
 * Use STACK variant on one algorithm if performance or batch is required.
 */

#pragma once

#ifndef __QDEFENDER__
#define __QDEFENDER__
#endif

#include <oqs/oqs.h>
#include <stdio.h>
#include <string.h>

/**
 * print array un hex mode, truncate if too long
 */
void log8(char *text, uint8_t *data, size_t len);
void log32(char *text, uint32_t *data, uint32_t datalength);

/*
 * Handy object to check algorithm key sizes
 */
typedef struct CRYPTO_PARAMS {
  size_t pk;
  size_t sk;
  size_t ct;
  size_t ss;
  size_t sig;
} CRYPTO_PARAMS;

/*****************************************************************************
 *                       ENCAPSULATION (KEM)
 *
 * Usage:
 *  - Use the KEM struct as the only parameter.
 *    It will containt the results of any operation.
 * - After finish, call destroy() to free memory.
 * ***************************************************************************/

struct KEM_NAMES {
  const char *ntru1;
  const char *ntru3;
  const char *ntru5;
  const char *kyber1;
  const char *kyber3;
  const char *kyber5;
} KEM_NAMES;

struct KEM_NAMES KEM_NAMES = {.ntru1 = OQS_KEM_alg_ntru_hps2048509,
                              .ntru3 = OQS_KEM_alg_ntru_hps2048677,
                              .ntru5 = OQS_KEM_alg_ntru_hps4096821,
                              .kyber1 = OQS_KEM_alg_kyber_512_90s,
                              .kyber3 = OQS_KEM_alg_kyber_768_90s,
                              .kyber5 = OQS_KEM_alg_kyber_1024_90s};

typedef struct KEM {
  char *name;
  uint8_t *public_key;
  uint8_t *secret_key;
  uint8_t *ciphertext;
  uint8_t *shared_secret;
} KEM;

OQS_KEM *get_kem_algorithm(const char *name);

/**
 * Init encapsulation
 *
 * Note: this function is for external calls exclusively.
 * For C-type calls or static linkage, the params can be extracted from kem.h
 * The can generate their own pointers in the KEM but
 * they are responsible to free the memory
 */
int KEM_init(const char *name, CRYPTO_PARAMS *params);

/**
 * Create encapsulation object and add the required arrays memory.
 * By using this function, the memory is safely freed wne calling destroy.
 *
 * @param name the name of algorithm. Use KEM_NAMES or use any of the available
 * names at kem.h
 */
KEM KEM_create(const char *name);

void KEM_destroy(KEM *kem);

int KEM_generate_keys(KEM *kem);

int KEM_encapsulate(KEM *kem);

int KEM_decapsulate(KEM *kem);

/*****************************************************************************
 *                        SIGNATURE (SIG)
 *
 *  * Usage:
 *  - Use the SIG struct as the primary parameter.
 *  - Since SIG requires also an input, the message parameter
 *     memory management must be done by the developer.
 *  - So call destroy() but also free(message).
 *
 * ***************************************************************************/

struct SIG_NAMES {
  const char *dilithium2;
  const char *dilithium3;
  const char *dilithium5;
  const char *falcon1;
  const char *falcon5;
  const char *sphincs1;
  const char *rainbow1;
};

struct SIG_NAMES SIG_NAMES = {
    .dilithium2 = OQS_SIG_alg_dilithium_2,
    .dilithium3 = OQS_SIG_alg_dilithium_3,
    .dilithium5 = OQS_SIG_alg_dilithium_5,
    .falcon1 = OQS_SIG_alg_falcon_512,
    .falcon5 = OQS_SIG_alg_falcon_1024,
    .sphincs1 = OQS_SIG_alg_sphincs_haraka_128f_robust,
    .rainbow1 = OQS_SIG_alg_rainbow_I_compressed};

typedef struct SIG {
  // message is not a field because it can be a huge
  char *name;
  uint8_t *public_key;
  uint8_t *secret_key;
  uint8_t *signature;
  size_t signature_len;  // depending on the algorithm, signature output len can
                         // vary (eg:Falcon) so careful with that!
} SIG;

OQS_SIG *get_sig_algorithm(const char *name);

int SIG_init(const char *name, CRYPTO_PARAMS *params);

/**
 * Create signature object
 *
 * @param name  the name of algorithm. Use SIG_NAMES or use any of the available
 * names at sig.h
 * @return SIG
 */
SIG SIG_create(const char *name);

void SIG_destroy(SIG *sig);

int SIG_generate_keys(SIG *sig);

/**
 * IMPORTANT: some signatures have variable length output (eg:Falcon).
 * That is why we need a signature outuput lenght.
 * In most cases the value is not needed because the rest are padded in the
 * sig. So careful when reusing signature buffer
 */
int SIG_sign(SIG *sig, uint8_t *message, size_t message_len);
int SIG_verify(SIG *sig, uint8_t *message, size_t message_len);