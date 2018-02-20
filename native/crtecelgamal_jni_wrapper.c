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

#include <jni.h>
#include "ecelgamal.h"


jbyteArray as_byte_array(JNIEnv *env, unsigned char *buf, int len) {
    jbyteArray array = (*env)->NewByteArray(env, len);
    (*env)->SetByteArrayRegion(env, array, 0, len, (jbyte *) buf);
    return array;
}

unsigned char *as_unsigned_char_array(JNIEnv *env, jbyteArray array, int *len) {
    *len = (*env)->GetArrayLength(env, array);
    return (unsigned char *) (*env)->GetByteArrayElements(env, array, 0);
}

void free_jvm_char_array(JNIEnv *env, jbyteArray array, unsigned char * buff) {
    (*env)->ReleaseByteArrayElements(env, array, (jbyte *) buff, 0);
}


void get_key(JNIEnv *env, gamal_key_t key, jbyteArray array) {
    int buff_len;
    unsigned char *buffer = as_unsigned_char_array(env, array, &buff_len);
    decode_key(key, buffer, buff_len);
    free_jvm_char_array(env, array, buffer);
}

void get_cipher(JNIEnv *env, gamal_ciphertext_t cipher, jbyteArray array) {
    int buff_len;
    unsigned char *buffer = as_unsigned_char_array(env, array, &buff_len);
    decode_ciphertext(cipher, buffer, buff_len);
    free_jvm_char_array(env, array, buffer);
}

bsgs_table_t *table = NULL;

jint Java_ch_ethz_dsg_ecelgamal_ECElGamal_initEcElGamal(JNIEnv *env,
                                  jobject javaThis, jint curve_id) {
    return (jint) gamal_init((int) curve_id);
}

jint Java_ch_ethz_dsg_ecelgamal_ECElGamal_deinitECElGamal(JNIEnv *env,
                                    jobject javaThis) {
    if (table != NULL) {
        gamal_free_bsgs_table(*table);
        free(table);
        table = NULL;
    }
    return (jint) gamal_deinit();
}

jbyteArray Java_ch_ethz_dsg_ecelgamal_ECElGamal_generateKey(JNIEnv *env, jobject javaThis) {
    gamal_key_t key;
    unsigned char *buffer;
    size_t key_size;
    jbyteArray res;

    gamal_generate_keys(key);
    key_size = get_encoded_key_size(key, 0);
    buffer = (unsigned char *) malloc(key_size);
    encode_key(buffer, (int) key_size, key, 0);
    res = as_byte_array(env, buffer, (int) key_size);

    free(buffer);
    gamal_key_clear(key);
    return res;
}

jbyteArray Java_ch_ethz_dsg_ecelgamal_ECElGamal_encrypt(JNIEnv *env,
                                        jobject javaThis, jlong value,
                                        jbyteArray key_oct) {
    gamal_key_t key;
    gamal_ciphertext_t ciphertext;
    unsigned char *buffer;
    size_t cipher_size;
    jbyteArray res;

    get_key(env, key, key_oct);
    gamal_encrypt(ciphertext, key, (dig_t) value);

    cipher_size = get_encoded_ciphertext_size(ciphertext);
    buffer = (unsigned char *) malloc(cipher_size);
    encode_ciphertext(buffer, (int) cipher_size, ciphertext);
    res = as_byte_array(env, buffer, (int) cipher_size);

    free(buffer);
    gamal_key_clear(key);
    gamal_cipher_clear(ciphertext);
    return res;
}

jlong Java_ch_ethz_dsg_ecelgamal_ECElGamal_decrypt(JNIEnv *env, jobject javaThis, jbyteArray ciphertext_oct,
                                   jbyteArray key_oct, jboolean use_bsgs) {
    gamal_key_t key;
    gamal_ciphertext_t ciphertext;
    dig_t value = 0;

    get_key(env, key, key_oct);
    get_cipher(env, ciphertext, ciphertext_oct);

    if (use_bsgs) {
        if (table == NULL) {
            table = malloc(sizeof(bsgs_table_t));
            gamal_init_bsgs_table(*table, 1L<<16);
        }

        if(gamal_decrypt(&value, key, ciphertext, *table)) {
            (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/Exception"), "Error on decryption");
        }
    } else {
        if(gamal_decrypt(&value, key, ciphertext, NULL)) {
            (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/Exception"), "Error on decryption");
        }
    }

    gamal_key_clear(key);
    gamal_cipher_clear(ciphertext);
    return (jlong) value;
}

jbyteArray Java_ch_ethz_dsg_ecelgamal_ECElGamal_homAdd(JNIEnv *env, jobject javaThis, jbyteArray ciphertext_1_oct,
                                       jbyteArray ciphertext_2_oct) {
    gamal_ciphertext_t ciphertext1, ciphertext2;
    unsigned char *buffer;
    size_t cipher_size;
    jbyteArray res;

    get_cipher(env, ciphertext1, ciphertext_1_oct);
    get_cipher(env, ciphertext2, ciphertext_2_oct);

    gamal_add(ciphertext1, ciphertext1, ciphertext2);

    cipher_size = get_encoded_ciphertext_size(ciphertext1);
    buffer = (unsigned char *) malloc((size_t) cipher_size);
    encode_ciphertext(buffer, (int) cipher_size, ciphertext1);
    res = as_byte_array(env, buffer, (int) cipher_size);

    free(buffer);
    gamal_cipher_clear(ciphertext1);
    gamal_cipher_clear(ciphertext2);
    return res;
}

jint Java_ch_ethz_dsg_ecelgamal_ECElGamal_initBsgsTable(JNIEnv *env, jobject javaThis,
                                        jint table_size) {
    table = malloc(sizeof(bsgs_table_t));
    gamal_init_bsgs_table(*table, (dig_t) table_size);
    return 0;
}

jint Java_ch_ethz_dsg_ecelgamal_ECElGamal_getPointSize(JNIEnv *env, jobject javaThis) {
    return gamal_get_point_compressed_size();
}