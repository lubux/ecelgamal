/*
 * Copyright (c) 2018, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Author:
 *       Lukas Burkhalter <lubu@inf.ethz.ch>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef ECELGAMAL_ECELGAMAL_H
#define ECELGAMAL_ECELGAMAL_H

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <inttypes.h>
#include "uthash.h"

#define DEFAULT_CURVE NID_X9_62_prime192v1
#define CURVE_256_SEC NID_X9_62_prime256v1

#define MAX_BITS 32

struct gamal_key {
    char is_public;
    EC_POINT *Y;
    BIGNUM *secret;
};

typedef struct gamal_key *gamal_key_ptr;
typedef struct gamal_key gamal_key_t[1];
typedef uint64_t dig_t;

size_t get_encoded_key_size(gamal_key_t key, int compressed);
int encode_key(unsigned char* buff, int size, gamal_key_t key, int compressed);
int decode_key(gamal_key_t key, unsigned char* buff, int size);

struct gamal_ciphertext {
    EC_POINT *C1;
    EC_POINT *C2;
};

typedef struct gamal_ciphertext *gamal_ciphertext_ptr;
typedef struct gamal_ciphertext gamal_ciphertext_t[1];

size_t get_encoded_ciphertext_size(gamal_ciphertext_t ciphertext);
int encode_ciphertext(unsigned char* buff, int size, gamal_ciphertext_t ciphertext);
int decode_ciphertext(gamal_ciphertext_t ciphertext, unsigned char* buff, int size);

typedef struct bsgs_hash_table_entry {
    unsigned char *key;
    uint32_t value;
    UT_hash_handle hh;
} bsgs_hash_table_entry_t;

struct bsgs_table_s {
    bsgs_hash_table_entry_t *table;
    EC_POINT *mG, *mG_inv;
    EC_GROUP *group;
    dig_t tablesize;
};
typedef struct bsgs_table_s *bsgs_table_ptr;
typedef struct bsgs_table_s bsgs_table_t[1];

/**
 * Inits the library with the given curve
 */
int gamal_init(int curve_id);

/**
 * Deinits the library
 * @return
 */
int gamal_deinit();

/**
 * Returns the EC_Group (elliptic curve group) struct if initialized
 */
EC_GROUP *gamal_get_current_group();

/**
 * Returns the encded size of an EC-Point in this group.
 */
int gamal_get_point_compressed_size();

/**
 * Inititlaizes the baby-step-giant-step table.
 * @param the table
 * @param the number of elemnts to store in the table
 * @return
 */
int gamal_init_bsgs_table(bsgs_table_t table, dig_t size);

/**
 * Frees the memory of the table
 * @param table
 * @return
 */
int gamal_free_bsgs_table(bsgs_table_t table);

int gamal_key_clear(gamal_key_t keys);
int gamal_key_to_public(gamal_key_t pub, gamal_key_t priv);
int gamal_cipher_clear(gamal_ciphertext_t cipher);
int gamal_cipher_new(gamal_ciphertext_t cipher);

/**
 * Generates an EC-Elgamal key pair
 * @param keys the EC-ElGamal keypair
 * @return
 */
int gamal_generate_keys(gamal_key_t keys);

/**
 * Encrypts an Integer with additadive homomorphic EC-ElGamal
 * @param ciphertext
 * @param key
 * @param plaintext
 * @return
 */
int gamal_encrypt(gamal_ciphertext_t ciphertext, gamal_key_t key, dig_t plaintext);

/**
 * Decrypts an EC-Elgamal ciphertext
 * @param res the resulting plaintext integer
 * @param key
 * @param ciphertext
 * @param table if NULL bruteforce is used
 * @return
 */
int gamal_decrypt(dig_t *res, gamal_key_t key, gamal_ciphertext_t ciphertext, bsgs_table_t table);

/**
 * Adds two EC-Elgamal ciphertext and stores it in res.
 * @param res the resulting ciphertext
 * @param ciphertext1
 * @param ciphertext2
 * @return
 */
int gamal_add(gamal_ciphertext_t res, gamal_ciphertext_t ciphertext1, gamal_ciphertext_t ciphertext2);

#endif //ECELGAMAL_ECELGAMAL_H
