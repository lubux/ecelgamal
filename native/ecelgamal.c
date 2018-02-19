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

#include "ecelgamal.h"

#define KEY_UNCOMPRESSED 0
#define KEY_COMPRESSED 1
#define KEY_PUBLIC 2


EC_POINT *multiply_constant(const EC_POINT *in, const BIGNUM *n, EC_GROUP *curve_group) {
    EC_POINT *res;
    BIGNUM *bn1;
    BN_CTX *ctx;

    bn1 = BN_new();
    ctx = BN_CTX_new();
    BN_zero(bn1);
    res = EC_POINT_new(curve_group);
    EC_POINT_mul(curve_group, res, bn1, in, n, ctx);

    BN_free(bn1);
    BN_CTX_free(ctx);
    return res;
}

EC_POINT *multiply_generator(const BIGNUM *n, EC_GROUP *curve_group) {
    return multiply_constant(EC_GROUP_get0_generator(curve_group), n, curve_group);
}


char *point_to_string(EC_GROUP *curve_group, const EC_POINT *point) {
    BN_CTX *ctx;
    char *s;
    point_conversion_form_t form = POINT_CONVERSION_COMPRESSED;
    ctx = BN_CTX_new();
    s = EC_POINT_point2hex(curve_group, point, form, ctx);
    BN_CTX_free(ctx);
    return s;
}

int add_value_to_table(bsgs_table_t table, EC_POINT *point, uint32_t value) {
    unsigned char* point_key;
    BN_CTX *ctx = BN_CTX_new();
    size_t point_size = EC_POINT_point2oct(table->group, point, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    bsgs_hash_table_entry_t * new_entry = (bsgs_hash_table_entry_t *) malloc(sizeof(bsgs_hash_table_entry_t));
    point_key = (unsigned char*) malloc(point_size);
    EC_POINT_point2oct(table->group, point, POINT_CONVERSION_COMPRESSED, point_key, point_size, ctx);

    new_entry->key = point_key;
    new_entry->value = value;
    HASH_ADD_KEYPTR(hh, table->table, point_key, point_size, new_entry);
    BN_CTX_free(ctx);
    return 0;
}

int bsgs_table_init(EC_GROUP *curve_group, bsgs_table_t table, dig_t t_size) {
    dig_t count = 0;
    BIGNUM *bn_size;
    EC_POINT *cur_point;
    const EC_POINT *gen;
    BN_CTX *ctx = BN_CTX_new();

    gen = EC_GROUP_get0_generator(curve_group);
    table->table = NULL;
    table->group = curve_group;

    //set Table metadata
    bn_size = BN_new();
    BN_set_word(bn_size,  (BN_ULONG) t_size);
    table->tablesize = t_size;
    table->mG = multiply_constant(gen, bn_size, curve_group);
    BN_set_negative(bn_size, 1);
    table->mG_inv = multiply_constant(gen, bn_size, curve_group);
    BN_free(bn_size);


    gen = EC_GROUP_get0_generator(curve_group);
    cur_point = EC_POINT_new(curve_group);
    EC_POINT_set_to_infinity(curve_group, cur_point);
    for (; count <= t_size; count++) {
        add_value_to_table(table, cur_point, count);
        EC_POINT_add(curve_group, cur_point, cur_point, gen, ctx);
    }
    EC_POINT_free(cur_point);
    BN_CTX_free(ctx);
    return 0;
}

size_t bsgs_table_get_size(bsgs_table_t bsgs_table) {
    return 0;
}

int bsgs_table_free(bsgs_table_t bsgs_table) {
    bsgs_hash_table_entry_t *tmp, *current;
    HASH_ITER(hh, bsgs_table->table, current, tmp) {
        HASH_DEL(bsgs_table->table, current);
        free(current->key);
        free(current);
    }
    EC_POINT_free(bsgs_table->mG);
    EC_POINT_free(bsgs_table->mG_inv);
    return 0;
}

int get_power_from_table(uint64_t *power, bsgs_table_t bsgs_table, EC_POINT *lookup_point) {
    unsigned char* point_key;
    BN_CTX *ctx = BN_CTX_new();
    size_t point_size = EC_POINT_point2oct(bsgs_table->group, lookup_point, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    bsgs_hash_table_entry_t * entry;
    point_key = (unsigned char*) malloc(point_size);
    EC_POINT_point2oct(bsgs_table->group, lookup_point, POINT_CONVERSION_COMPRESSED, point_key, point_size, ctx);

    HASH_FIND_BIN(bsgs_table->table, point_key, point_size, entry);
    BN_CTX_free(ctx);
    free(point_key);

    if (entry == NULL)
        return -1;
    *power = (uint64_t) entry->value;
    return 0;
}


int solve_ecdlp_bsgs(bsgs_table_t bsgs_table, uint64_t *result, EC_POINT *M, int64_t maxIt) {
    uint64_t j = 0, i = 0;
    int ok;
    EC_GROUP *curve_group = bsgs_table->group;
    EC_POINT *curPoint = EC_POINT_dup(M, curve_group);
    EC_POINT *curPointNeg = EC_POINT_dup(M, curve_group);
    BN_CTX *ctx = BN_CTX_new();

    while (i <= maxIt) {
        ok = get_power_from_table(&j, bsgs_table, curPoint);
        if (ok == 0) {
            *result = i * bsgs_table->tablesize + j;
            break;
        }
        EC_POINT_add(curve_group, curPoint, curPoint, bsgs_table->mG_inv, ctx);
        i = i + 1;
    }

    if (i > maxIt) {
        return -1;
    }

    EC_POINT_free(curPoint);
    EC_POINT_free(curPointNeg);
    BN_CTX_free(ctx);
    return 0;
}

// Finds the value x with brute force s.t. M=xG
int solve_dlog_brute(EC_GROUP *curve_group, EC_POINT *M, uint64_t *x, dig_t max_it) {
    EC_POINT *cur;
    const EC_POINT *G;
    uint64_t max, x_local = 1;
    BN_CTX *ctx = BN_CTX_new();
    max = (int64_t) max_it;

    cur = EC_POINT_new(curve_group);
    G = EC_GROUP_get0_generator(curve_group);
    EC_POINT_set_to_infinity(curve_group, cur);

    if (EC_POINT_is_at_infinity(curve_group, M)) {
        *x = 0;
        return 0;
    } else {
        for (; x_local < max; (*x) = x_local++) {
            EC_POINT_add(curve_group, cur, cur, G, ctx);
            if (EC_POINT_cmp(curve_group, cur, M, ctx) == 0) {
                break;
            }
        }
        *x = x_local;
    }
    EC_POINT_free(cur);
    BN_CTX_free(ctx);
    return 0;
}

// API IMPLEMENTATION

//the ec group used
EC_GROUP *init_group = NULL;

int gamal_init(int curve_id) {
    init_group = EC_GROUP_new_by_curve_name(curve_id);
    return 0;
}

int gamal_deinit() {
    if (init_group != NULL) {
        EC_GROUP_free(init_group);
        init_group = NULL;
    }
    return 0;
}


int gamal_init_bsgs_table(bsgs_table_t table, dig_t size) {
    return bsgs_table_init(init_group, table, size);
}


int gamal_free_bsgs_table(bsgs_table_t table) {
    bsgs_table_free(table);
    return 0;
}

int gamal_key_clear(gamal_key_t key) {
    EC_POINT_clear_free(key->Y);
    if (!key->is_public) {
        BN_clear_free(key->secret);
    }
    return 0;
}

int gamal_key_to_public(gamal_key_t pub, gamal_key_t priv) {
    pub->is_public = 1;
    pub->Y = EC_POINT_dup(priv->Y, init_group);
    return 0;
}

int gamal_cipher_clear(gamal_ciphertext_t cipher) {
    EC_POINT_clear_free(cipher->C1);
    EC_POINT_clear_free(cipher->C2);
    return 0;
}

int gamal_cipher_new(gamal_ciphertext_t cipher) {
    cipher->C1 = EC_POINT_new(init_group);
    cipher->C2 = EC_POINT_new(init_group);
    return 0;
}

int gamal_generate_keys(gamal_key_t keys) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *ord, *key;

    ord = BN_new();
    key = BN_new();
    keys->Y = EC_POINT_new(init_group);

    EC_GROUP_get_order(init_group, ord, ctx);

    BN_rand_range(key, ord);
    keys->is_public = 0;
    keys->Y = multiply_generator(key, init_group);
    keys->secret = key;
    BN_free(ord);
    BN_CTX_free(ctx);
    return 0;
}

int gamal_encrypt(gamal_ciphertext_t ciphertext, gamal_key_t key, dig_t plaintext) {
    BIGNUM *bn_plain, *ord, *rand;
    BN_CTX *ctx = BN_CTX_new();

    bn_plain = BN_new();
    ord = BN_new();
    rand = BN_new();
    ciphertext->C2 = EC_POINT_new(init_group);

    EC_GROUP_get_order(init_group, ord, ctx);
    BN_rand_range(rand, ord);

    BN_set_word(bn_plain, plaintext);

    ciphertext->C1 = multiply_generator(rand, init_group);
    EC_POINT_mul(init_group, ciphertext->C2, bn_plain, key->Y, rand, ctx);

    BN_clear_free(rand);
    BN_free(ord);
    BN_free(bn_plain);
    BN_CTX_free(ctx);
    return 0;
}

// if table == NULL use bruteforce
int gamal_decrypt(dig_t *res, gamal_key_t key, gamal_ciphertext_t ciphertext, bsgs_table_t table) {
    EC_POINT *M;
    uint64_t plaintext;
    BN_CTX *ctx = BN_CTX_new();


    M = multiply_constant(ciphertext->C1, key->secret, init_group);
    EC_POINT_invert(init_group, M, ctx);
    EC_POINT_add(init_group, M, ciphertext->C2, M, ctx);

    if (table != NULL) {
        solve_ecdlp_bsgs(table, &plaintext, M, 1L << MAX_BITS);
    } else {
        solve_dlog_brute(init_group, M, &plaintext, 1L << MAX_BITS);
    }
    *res = (dig_t) plaintext;

    BN_CTX_free(ctx);
    EC_POINT_clear_free(M);
    return 0;
}


int gamal_add(gamal_ciphertext_t res, gamal_ciphertext_t ciphertext1, gamal_ciphertext_t ciphertext2) {
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT_add(init_group, res->C1, ciphertext1->C1, ciphertext2->C1, ctx);
    EC_POINT_add(init_group, res->C2, ciphertext1->C2, ciphertext2->C2, ctx);
    BN_CTX_free(ctx);
    return 0;
}

EC_GROUP *gamal_get_current_group() {
    return init_group;
}

int gamal_get_point_compressed_size() {
    BN_CTX *ctx = BN_CTX_new();
    int res = (int) EC_POINT_point2oct(init_group, EC_GROUP_get0_generator(init_group),
                              POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    BN_CTX_free(ctx);
    return res;
}


// ENCODING + DECODING

void write_size(unsigned char *buffer, size_t size) {
    buffer[0] = (unsigned char) ((size >> 8) & 0xFF);
    buffer[1] = (unsigned char) (size & 0xFF);
}

size_t read_size(unsigned char *buffer) {
    return ((uint8_t) buffer[0] << 8) | ((uint8_t) buffer[1]);
}

size_t get_encoded_ciphertext_size(gamal_ciphertext_t ciphertext) {
    return (size_t) gamal_get_point_compressed_size()*2;
}

int encode_ciphertext(unsigned char *buff, int size, gamal_ciphertext_t ciphertext) {
    unsigned char *cur_ptr = buff;
    size_t len_point, tmp;
    BN_CTX *ctx = BN_CTX_new();
    len_point = (size_t) gamal_get_point_compressed_size();
    if (size < (len_point * 2))
        return -1;
    tmp = EC_POINT_point2oct(init_group, ciphertext->C1, POINT_CONVERSION_COMPRESSED, cur_ptr, len_point, ctx);
    cur_ptr += len_point;
    if (tmp != len_point)
        return -1;
    tmp = EC_POINT_point2oct(init_group, ciphertext->C2, POINT_CONVERSION_COMPRESSED, cur_ptr, len_point, ctx);
    if (tmp != len_point)
        return -1;
    BN_CTX_free(ctx);
    return 0;
}

int decode_ciphertext(gamal_ciphertext_t ciphertext, unsigned char *buff, int size) {
    size_t len_point;
    BN_CTX *ctx = BN_CTX_new();
    unsigned char *cur_ptr = buff;
    len_point = (size_t) gamal_get_point_compressed_size();
    if (size < len_point*2)
        return -1;

    ciphertext->C1 = EC_POINT_new(init_group);
    EC_POINT_oct2point(init_group, ciphertext->C1, cur_ptr, len_point, ctx);
    cur_ptr += len_point;

    ciphertext->C2 = EC_POINT_new(init_group);
    EC_POINT_oct2point(init_group, ciphertext->C2, cur_ptr, len_point, ctx);

    BN_CTX_free(ctx);
    return 0;
}

size_t get_encoded_key_size(gamal_key_t key, int compressed) {
    size_t size = 1;
    BN_CTX *ctx = BN_CTX_new();
    if(!key->is_public) {
        if (compressed)
            size +=  BN_num_bytes(key->secret);
        else
            size +=  BN_num_bytes(key->secret) +
                    EC_POINT_point2oct(init_group, key->Y, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    } else {
        size += EC_POINT_point2oct(init_group, key->Y, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    }
    BN_CTX_free(ctx);
    return size;
}
int encode_key(unsigned char *buff, int size, gamal_key_t key, int compressed) {
    size_t len_point;
    unsigned char *cur_ptr = buff;
    size_t size_data;
    BN_CTX *ctx = BN_CTX_new();

    len_point = (size_t) gamal_get_point_compressed_size();

    if (size < 3)
        return -1;

    if (key->is_public) {
        buff[0] = KEY_PUBLIC;
    } else {
        if (compressed)
            buff[0] = KEY_COMPRESSED;
        else
            buff[0] = KEY_UNCOMPRESSED;

    }

    cur_ptr++;
    if (key->is_public) {
        size_data = len_point;
    } else {
        if (compressed)
            size_data = (size_t) BN_num_bytes(key->secret);
        else
            size_data = (size_t) BN_num_bytes(key->secret) + len_point;

    }

    if (size < 1 + size_data)
        return  -1;

    if (key->is_public) {
        EC_POINT_point2oct(init_group, key->Y, POINT_CONVERSION_COMPRESSED, cur_ptr, size_data, ctx);
    } else {
        if (compressed) {
            BN_bn2bin(key->secret, cur_ptr);
        } else {
            EC_POINT_point2oct(init_group, key->Y, POINT_CONVERSION_COMPRESSED, cur_ptr, len_point, ctx);
            cur_ptr += len_point;
            BN_bn2bin(key->secret, cur_ptr);
        }
    }
    BN_CTX_free(ctx);
    return 0;
}
int decode_key(gamal_key_t key, unsigned char* buff, int size) {
    size_t len_point;
    char is_pub;
    int is_compressed = 0, decode_id = 0;
    unsigned char *cur_ptr = buff;
    size_t size_data;
    BN_CTX *ctx = BN_CTX_new();

    len_point = (size_t) gamal_get_point_compressed_size();

    if (size < 3)
        return -1;

    decode_id = (int) buff[0];

    if (decode_id == KEY_COMPRESSED)
        is_compressed = 1;

    if (decode_id == KEY_PUBLIC)
        is_pub = 1;
    else
        is_pub = 0;

    key->secret = BN_new();
    cur_ptr++;
    key->is_public = is_pub;
    if (key->is_public) {
        size_data = len_point;
    } else {
        size_data = (size_t) size - 1;
    }

    if (size < 1 + size_data)
        return  -1;
    if (is_pub) {
        key->Y = EC_POINT_new(init_group);
        EC_POINT_oct2point(init_group, key->Y, cur_ptr, size_data, ctx);
    } else {
        if (is_compressed) {
            BN_bin2bn(cur_ptr, (int) size_data, key->secret);
            key->Y = multiply_generator(key->secret, init_group);
        } else {
            key->Y = EC_POINT_new(init_group);
            EC_POINT_oct2point(init_group, key->Y, cur_ptr, len_point, ctx);
            cur_ptr += len_point;
            BN_bin2bn(cur_ptr, (int) size_data - (int) len_point, key->secret);
        }
    }
    BN_CTX_free(ctx);
    return 0;
}



