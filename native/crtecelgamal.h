//
// Created by Lukas Burkhalter on 02.02.18.
//

#ifndef ECELGAMAL_CRTECELGAMAL_H
#define ECELGAMAL_CRTECELGAMAL_H

#include "ecelgamal.h"

#define DEFAULT_32_INTEGER_PARAMS 1
#define DEFAULT_64_INTEGER_PARAMS 2

struct crt_params {
    int numsplits;
    BIGNUM **splits;
    BIGNUM *prime;
};
typedef struct crt_params *crtgamal_params_ptr;
typedef struct crt_params crtgamal_params_t[1];

/**
 * Generates new CRT-params
 * @param params
 * @param dbits the number of bits per prime
 * @param num_primes the number of CRT-Partitions
 * @return
 */
int crt_params_generate(crtgamal_params_t params, int dbits, int num_primes);

/**
 * Initializes the CRT-params with default parameters
 * @param params
 * @param default_params_id (ex. DEFAULT_32_INTEGER_PARAMS, DEFAULT_64_INTEGER_PARAMS)
 * @return
 */
int crt_params_create_default(crtgamal_params_t params, char default_params_id);
int crt_params_free(crtgamal_params_t params);

struct crtgamal_key {
    crtgamal_params_t params;
    gamal_key_t key;
};
typedef struct crtgamal_key *crtgamal_key_ptr;
typedef struct crtgamal_key crtgamal_key_t[1];

struct crtgamal_ciphertext {
    int num_ciphertexts;
    gamal_ciphertext_t *ciphertexts;
};
typedef struct crtgamal_ciphertext *crtgamal_ciphertext_ptr;
typedef struct crtgamal_ciphertext crtgamal_ciphertext_t[1];

size_t crt_get_encoded_ciphertext_size(crtgamal_ciphertext_t ciphertext);
int crt_encode_ciphertext(unsigned char* buff, int size, crtgamal_ciphertext_t ciphertext);
int crt_decode_ciphertext(crtgamal_ciphertext_t ciphertext, unsigned char* buff, int size);

int crtgamal_ciphertext_new(crtgamal_ciphertext_t ciphertext, int num_partitions);
int crtgamal_ciphertext_free(crtgamal_ciphertext_t ciphertext);

int crtgamal_generate_keys_with_params(crtgamal_key_t keys, int dbits, int num_primes);
int crtgamal_generate_keys(crtgamal_key_t keys, crtgamal_params_t params);
int crtgamal_keys_clear(crtgamal_key_t keys);

/**
 * Encrypts and Integer with additative homomorphic EC-ELGamal with CRT-optimizations
 * @param ciphertext
 * @param key
 * @param plaintext
 * @return
 */
int crtgamal_encrypt(crtgamal_ciphertext_t ciphertext, crtgamal_key_t key, dig_t plaintext);

/**
 * Decrypts a CRT-EC-Elgamal ciphertext
 * @param res the rsulting Integer
 * @param key
 * @param ciphertext
 * @param table if NULL bruteforce is used
 * @return
 */
int crtgamal_decrypt(dig_t *res, crtgamal_key_t key, crtgamal_ciphertext_t ciphertext, bsgs_table_t table);

/**
 * Adds two CRT-EC-ElGamal ciphertexts and stores the result in res.
 * @param res the resulting ciphertext
 * @param ciphertext1
 * @param ciphertext2
 * @return
 */
int crtgamal_add(crtgamal_ciphertext_t res, crtgamal_ciphertext_t ciphertext1, crtgamal_ciphertext_t ciphertext2);

/**
 * Initializes the library with the given elliptic curve
 * @param curve_id (ex. DEFAULT_CURVE, CURVE_256_SEC)
 * @return
 */
int crtgamal_init(int curve_id);

/**
 * Deinitializes the library and frees memory
 * @return
 */
int crtgamal_deinit();

#endif //ECELGAMAL_CRTECELGAMAL_H
