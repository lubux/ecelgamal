//
// Created by Lukas Burkhalter on 02.02.18.
//

#include "crtecelgamal.h"

uint64_t small_integer_primes[2] = {119963L, 103997L};

uint64_t big_integer_primes[3] = {3624683L, 3356513L, 3315317L};

int crt_params_generate(crtgamal_params_t params, int dbits, int num_primes) {
    BIGNUM *d;
    BIGNUM **ds;
    BN_CTX *ctx = BN_CTX_new();
    int ok;
    ds = (BIGNUM **) malloc(num_primes * sizeof(BIGNUM *));
    d = BN_new();
    BN_set_word(d, 1);

    while (dbits * num_primes > BN_num_bits(d)) {
        for (int index=0; index< num_primes; index++) {
            ds[index] = BN_new();
            do {
                ok = 1;
                BN_generate_prime_ex(ds[index], dbits, 0, NULL, NULL, NULL);
                for (int i=0; i<index; i++) {
                    if (BN_cmp(ds[index], ds[i]) == 0) {
                        ok = 0;
                    }
                }
            } while (!ok);
            BN_mul(d, ds[index], d, ctx);
        }
    }
    params->numsplits = num_primes;
    params->prime = d;
    params->splits = ds;
    BN_CTX_free(ctx);
    return 0;
}

int create_params_from_default(crtgamal_params_t params, uint64_t *primes, int num_primes) {
    BIGNUM *d;
    BIGNUM **ds;
    BN_CTX *ctx = BN_CTX_new();

    ds = (BIGNUM **) malloc(num_primes * sizeof(BIGNUM *));
    d = BN_new();
    BN_set_word(d, 1);
    for (int iter=0; iter<num_primes; iter++) {
        ds[iter] = BN_new();
        BN_set_word(ds[iter], primes[iter]);
        BN_mul(d, d, ds[iter], ctx);
    }
    params->numsplits = num_primes;
    params->prime = d;
    params->splits = ds;
    BN_CTX_free(ctx);
    return 0;
}

int crt_params_create_default(crtgamal_params_t params, char default_params_id) {

    if (default_params_id == DEFAULT_32_INTEGER_PARAMS) {
        create_params_from_default(params, small_integer_primes, 2);
    } else if (default_params_id == DEFAULT_64_INTEGER_PARAMS){
        create_params_from_default(params, big_integer_primes, 3);
    } else {
        return -1;
    }
    return 0;
}

int crt_params_free(crtgamal_params_t params) {
    BN_free(params->prime);
    for (int iter=0; iter < params->numsplits; iter++) {
        BN_free(params->splits[iter]);
    }
    return 0;
}

int solve_crt(BIGNUM *res, int count, BIGNUM **numbers, BIGNUM **primes, BIGNUM *prime) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *temp1, *temp2;

    BN_zero(res);
    temp1 = BN_new();
    temp2 = BN_new();

    for (int iter = 0; iter<count; iter++) {
        BN_div(temp1, NULL, prime, primes[iter], ctx);
        BN_mul(temp2, numbers[iter], temp1, ctx);
        BN_mod_inverse(temp1, temp1, primes[iter], ctx);
        BN_mul(temp2, temp2, temp1, ctx);
        BN_add(res, res, temp2);
    }

    BN_mod(res, res, prime, ctx);
    BN_CTX_free(ctx);
    BN_free(temp1);
    BN_free(temp2);
    return 0;
}

int crtgamal_generate_keys_with_params(crtgamal_key_t keys, int dbits, int num_primes) {
    gamal_generate_keys(keys->key);
    crt_params_generate(keys->params, dbits, num_primes);
    return 0;
}

int crtgamal_generate_keys(crtgamal_key_t keys, crtgamal_params_t params) {
    gamal_generate_keys(keys->key);
    keys->params->splits = params->splits;
    keys->params->numsplits = params->numsplits;
    keys->params->prime = params->prime;
    return 0;
}

int crtgamal_keys_clear(crtgamal_key_t keys) {
    gamal_key_clear(keys->key);
    return 0;
}

int crtgamal_encrypt(crtgamal_ciphertext_t ciphertext, crtgamal_key_t key, dig_t plaintext) {
    int num_Splits = key->params->numsplits;
    BIGNUM *t1, *plain_bn;
    BN_CTX *ctx = BN_CTX_new();
    t1 = BN_new();
    plain_bn = BN_new();
    BN_set_word(plain_bn, plaintext);

    crtgamal_ciphertext_new(ciphertext, num_Splits);
    for (int iter=0; iter < num_Splits; iter++) {
        BN_mod(t1, plain_bn, key->params->splits[iter], ctx);
        gamal_encrypt(ciphertext->ciphertexts[iter], key->key, BN_get_word(t1));
    }

    BN_free(t1);
    BN_free(plain_bn);
    BN_CTX_free(ctx);
    return 0;
}

int crtgamal_decrypt(dig_t *res, crtgamal_key_t key, crtgamal_ciphertext_t ciphertext, bsgs_table_t table) {
    int num_Splits = key->params->numsplits;
    BIGNUM **plaintexts, *result;

    if (ciphertext->num_ciphertexts != key->params->numsplits) {
        return -1;
    }

    result = BN_new();
    dig_t  temp_res;
    plaintexts = malloc(sizeof(BIGNUM*) * num_Splits);

    for (int iter=0; iter < num_Splits; iter++) {
        gamal_decrypt(&temp_res, key->key, ciphertext->ciphertexts[iter], table);
        plaintexts[iter] = BN_new();
        BN_set_word(plaintexts[iter], temp_res);
    }

    solve_crt(result, num_Splits, plaintexts, key->params->splits, key->params->prime);
    *res = BN_get_word(result);

    for (int iter=0; iter < num_Splits; iter++) {
        BN_free(plaintexts[iter]);
    }
    free(plaintexts);
    BN_free(result);
    return 0;
}

int crtgamal_add(crtgamal_ciphertext_t res, crtgamal_ciphertext_t ciphertext1, crtgamal_ciphertext_t ciphertext2) {
    int num_Splits = ciphertext1->num_ciphertexts;
    for (int iter=0; iter < num_Splits; iter++) {
        gamal_add(res->ciphertexts[iter], ciphertext1->ciphertexts[iter], ciphertext2->ciphertexts[iter]);
    }
    return 0;
}

int crtgamal_ciphertext_new(crtgamal_ciphertext_t ciphertext, int num_partitions) {
    ciphertext->num_ciphertexts = num_partitions;
    ciphertext->ciphertexts = malloc(sizeof(gamal_ciphertext_t) * num_partitions);
    return 0;
}

int crtgamal_ciphertext_free(crtgamal_ciphertext_t ciphertext) {
    for (int iter=0; iter < ciphertext->num_ciphertexts; iter++) {
        gamal_cipher_clear(ciphertext->ciphertexts[iter]);
    }
    free(ciphertext->ciphertexts);
    return 0;
}

int crtgamal_init(int curve_id) {
    gamal_init(curve_id);
    return 0;
}

int crtgamal_deinit() {
    gamal_deinit();
    return 0;
}


void write_size_local(unsigned char *buffer, int size) {
    buffer[0] = (unsigned char) (size & 0xFF);
}

int read_size_local(unsigned char *buffer) {
    return (int) buffer[0];
}

size_t crt_get_encoded_ciphertext_size(crtgamal_ciphertext_t ciphertext) {
    return (size_t) (gamal_get_point_compressed_size() * 2 * ciphertext->num_ciphertexts) + 1;
}

int crt_encode_ciphertext(unsigned char* buff, int size, crtgamal_ciphertext_t ciphertext) {
    EC_GROUP *group = gamal_get_current_group();
    int len_point, len_temp;
    BN_CTX *ctx = BN_CTX_new();
    unsigned char *cur_ptr = buff;

    if (ciphertext->num_ciphertexts < 1)
        return -1;

    len_point = gamal_get_point_compressed_size();

    if (size < ((len_point * 2 * ciphertext->num_ciphertexts) + 1))
        return -1;

    write_size_local(cur_ptr, ciphertext->num_ciphertexts);
    cur_ptr++;

    for (int iter=0; iter < ciphertext->num_ciphertexts; iter++) {
        len_temp = (int) EC_POINT_point2oct(group, ciphertext->ciphertexts[iter]->C1,
                                            POINT_CONVERSION_COMPRESSED, cur_ptr, (size_t) len_point, ctx);

        if (len_temp != len_point)
            return -1;
        cur_ptr += len_point;
        len_temp = (int) EC_POINT_point2oct(group, ciphertext->ciphertexts[iter]->C2,
                                            POINT_CONVERSION_COMPRESSED, cur_ptr, (size_t) len_point, ctx);

        if (len_temp != len_point)
            return -1;
        cur_ptr += len_point;
    }
    BN_CTX_free(ctx);
    return 0;
}


int crt_decode_ciphertext(crtgamal_ciphertext_t ciphertext, unsigned char* buff, int size) {
    BN_CTX *ctx = BN_CTX_new();
    unsigned char *cur_ptr = buff;
    EC_GROUP *group = gamal_get_current_group();
    int len_point, num_partitions;

    if (size < 1)
        return -1;

    len_point = gamal_get_point_compressed_size();
    num_partitions = read_size_local(cur_ptr);
    cur_ptr++;

    if (size < ((len_point * 2 * num_partitions) + 1))
        return -1;

    crtgamal_ciphertext_new(ciphertext, num_partitions);

    for (int iter=0; iter < ciphertext->num_ciphertexts; iter++) {
        gamal_cipher_new(ciphertext->ciphertexts[iter]);

        EC_POINT_oct2point(group, ciphertext->ciphertexts[iter]->C1, cur_ptr, (size_t) len_point, ctx);
        cur_ptr += len_point;

        EC_POINT_oct2point(group, ciphertext->ciphertexts[iter]->C2, cur_ptr, (size_t) len_point, ctx);
        cur_ptr += len_point;
    }
    BN_CTX_free(ctx);
    return 0;
}
