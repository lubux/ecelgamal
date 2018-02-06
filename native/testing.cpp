#include <iostream>
#include <chrono>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>


extern "C" {
    #include "ecelgamal.h"
    #include "crtecelgamal.h"
}

using namespace std::chrono;

int test1() {
    gamal_key_t key, key_decoded;
    gamal_ciphertext_t cipher, cipher_after;
    bsgs_table_t table;
    dig_t plain = 36435345, res, res2;
    unsigned char *buff;
    size_t size;

    gamal_init(DEFAULT_CURVE);

    gamal_generate_keys(key);
    gamal_encrypt(cipher, key, plain);

    std::cout << "key gen + enc ok" << std::endl;

    buff = (unsigned char *) malloc(get_encoded_ciphertext_size(cipher));
    encode_ciphertext(buff, 100000, cipher);
    decode_ciphertext(cipher_after, buff, 1000000);
    free(buff);

    size = get_encoded_key_size(key);
    buff = (unsigned char *) malloc(size);
    encode_key(buff, size, key);
    decode_key(key_decoded, buff, size);


    gamal_init_bsgs_table(table, 1L << 16);

    gamal_decrypt(&res, key, cipher_after, table);

    std::cout << "Before:  " << plain << " After: " << res << std::endl;
    gamal_free_bsgs_table(table);
    gamal_deinit();
    return 0;
}

void bench_elgamal(int num_entries, int tablebits) {
    gamal_key_t key;
    gamal_ciphertext_t cipher;
    dig_t plain, after;
    bsgs_table_t table;
    srand (time(NULL));
    double avg_enc = 0, avg_dec = 0;

    gamal_init(DEFAULT_CURVE);
    gamal_generate_keys(key);
    gamal_init_bsgs_table(table, (dig_t) 1L << tablebits);

    for (int iter=0; iter<num_entries; iter++) {
        plain = ((dig_t) rand()) * iter % (((dig_t)1L) << 32);

        high_resolution_clock::time_point t1 = high_resolution_clock::now();
        gamal_encrypt(cipher, key, plain);
        high_resolution_clock::time_point t2 = high_resolution_clock::now();
        auto enc_time = duration_cast<nanoseconds>(t2-t1).count();

        avg_enc += enc_time;

        t1 = high_resolution_clock::now();
        gamal_decrypt(&after, key, cipher, table);
        t2 = high_resolution_clock::now();
        auto dec_time = duration_cast<nanoseconds>(t2-t1).count();

        avg_dec += dec_time;
        std::cout << " ENC Time: " <<  enc_time / 1000000.0 << " DEC Time: " << dec_time / 1000000.0 << std::endl;
    }
    avg_enc = avg_enc / num_entries;
    avg_dec = avg_dec / num_entries;
    std::cout << "Avg ENC Time " <<  avg_enc / 1000000.0 << " Avg DEC Time " << avg_dec / 1000000.0 << std::endl;

    gamal_cipher_clear(cipher);
    gamal_key_clear(key);
    gamal_free_bsgs_table(table);
    gamal_deinit();
}

void test2() {
    crtgamal_params_t params;
    crtgamal_key_t key, key_decoded;
    crtgamal_ciphertext_t cipher, cipher_after;
    bsgs_table_t table;
    dig_t plain = 36435345, res, res2;
    unsigned char *buff;
    size_t size, size_ciphertext;

    crtgamal_init(DEFAULT_CURVE);
    crt_params_create_default(params, DEFAULT_32_INTEGER_PARAMS);

    crtgamal_generate_keys(key, params);
    crtgamal_encrypt(cipher, key, plain);

    std::cout << "key gen + enc ok" << std::endl;

    size_ciphertext = crt_get_encoded_ciphertext_size(cipher);
    buff = (unsigned char *) malloc(size_ciphertext);
    crt_encode_ciphertext(buff, (int) size_ciphertext, cipher);
    crt_decode_ciphertext(cipher_after, buff, (int) size_ciphertext);
    free(buff);

    //size = get_encoded_key_size(key);
    //buff = (unsigned char *) malloc(size);
    //encode_key(buff, size, key);
    //decode_key(key_decoded, buff, size);


    gamal_init_bsgs_table(table, 1L << 8);

    crtgamal_decrypt(&res, key, cipher_after, table);

    std::cout << "Before:  " << plain << " After: " << res << std::endl;
    gamal_free_bsgs_table(table);
    crt_params_free(params);
    crtgamal_ciphertext_free(cipher);
    crtgamal_ciphertext_free(cipher_after);
    gamal_deinit();
}

void bench_crtelgamal(int num_entries, int tablebits, int plainbits) {
    crtgamal_key_t key;
    crtgamal_params_t params;
    crtgamal_ciphertext_t cipher;
    dig_t plain, after;
    bsgs_table_t table;
    srand (time(NULL));
    double avg_enc = 0, avg_dec = 0;

    crtgamal_init(DEFAULT_CURVE);
    if (plainbits>32)
        crt_params_create_default(params, DEFAULT_64_INTEGER_PARAMS);
    else
        crt_params_create_default(params, DEFAULT_32_INTEGER_PARAMS);
    crtgamal_generate_keys(key, params);
    gamal_init_bsgs_table(table, (dig_t) 1L << tablebits);

    for (int iter=0; iter<num_entries; iter++) {
        //plain = ((dig_t) rand()) * iter % (((dig_t)1L) << plainbits);
        plain = (((dig_t)1L) << plainbits) - iter;

        high_resolution_clock::time_point t1 = high_resolution_clock::now();
        crtgamal_encrypt(cipher, key, plain);
        high_resolution_clock::time_point t2 = high_resolution_clock::now();
        auto enc_time = duration_cast<nanoseconds>(t2-t1).count();

        avg_enc += enc_time;

        t1 = high_resolution_clock::now();
        crtgamal_decrypt(&after, key, cipher, table);
        t2 = high_resolution_clock::now();
        auto dec_time = duration_cast<nanoseconds>(t2-t1).count();

        avg_dec += dec_time;
        std::cout << " ENC Time: " <<  enc_time / 1000000.0 << " DEC Time: " << dec_time / 1000000.0 << std::endl;

        if (after != plain)
            std::cout << "ERROR" << std::endl;
    }
    avg_enc = avg_enc / num_entries;
    avg_dec = avg_dec / num_entries;
    std::cout << "Avg ENC Time " <<  avg_enc / 1000000.0 << " Avg DEC Time " << avg_dec / 1000000.0 << std::endl;

    crtgamal_ciphertext_free(cipher);
    crtgamal_keys_clear(key);
    gamal_free_bsgs_table(table);
    gamal_deinit();
}

void test3() {


}


int main() {
    std::cout << "START" << std::endl;
    //test1();
    //test2();
    //test2();
    //bench_elgamal(100, 17);
    bench_crtelgamal(1000, 10, 64);
    return 0;
}