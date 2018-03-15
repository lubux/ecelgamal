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

package ch.ethz.dsg.ecelgamal;

import java.math.BigInteger;
import java.security.Key;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;

import org.scijava.nativelib.NativeLibraryUtil;

/**
 * Additive homomoprhic EC-El-Gamal wrapper around the native C implementation
 */
public class ECElGamal {

    public static int NID_X9_62_prime192v1 = 409;
    public static int NID_X9_62_prime239v1 = 412;
    public static int NID_X9_62_prime256v1 = 415;

    private static long[] default32BitParams = {1429L, 1931L, 1733L};
    private static long[] default64BitParams = {6607L, 8011L, 8171L, 8017L, 8111L};

    static {
        try {
            NativeLibraryUtil.loadNativeLibrary(ECElGamal.class, "ecelgamal-jni-wrapper");
        } catch (Exception e) {
            e.printStackTrace();
        }

        initEcElGamal(NID_X9_62_prime256v1);
    }

    public static synchronized void changeGroup(int newGroupID) {
        deinitECElGamal();
        initEcElGamal(newGroupID);
    }

    private static BigInteger solveCRT(BigInteger[] nums, BigInteger[] ds, BigInteger d) {
        BigInteger res = BigInteger.ZERO;
        for (int index=0; index<nums.length; index++) {
            BigInteger cur = nums[index];
            BigInteger di = ds[index];
            BigInteger temp = d.divide(di);
            cur = cur.multiply(temp).multiply(temp.modInverse(di));
            res = res.add(cur);
        }
        return res.mod(d);
    }


    public static CRTParams generateCRTParams(Random rand, int dBits, int numD) {
        BigInteger d = BigInteger.ONE;
        BigInteger[] ds = new BigInteger[numD];
        while (dBits*numD > d.bitLength()) {
            HashSet<BigInteger> before = new HashSet<>(numD);
            d = BigInteger.ONE;
            for (int index = 0; index < numD; index++) {
                BigInteger temp;
                do {
                    temp = BigInteger.probablePrime(dBits, rand);
                } while (before.contains(temp));
                before.add(temp);
                ds[index] = temp;
                d = d.multiply(temp);
            }

        }
        return new CRTParams(ds, d, dBits);
    }

    private static CRTParams generateParams(long[] primes, int numBits) {
        BigInteger[] ds = new BigInteger[primes.length];
        BigInteger d = BigInteger.ONE;
        for (int iter=0; iter < primes.length; iter++) {
            ds[iter] = BigInteger.valueOf(primes[iter]);
            d = d.multiply(ds[iter]);
        }
        return new CRTParams(ds, d, numBits);
    }

    /**
     * Returns the default CRT-Params for 32-bit integers
     * @return CRT-pramams for 32-bit integers
     */
    public static CRTParams getDefault32BitParams() {
        return generateParams(default32BitParams, 11);
    }

    /**
     * Returns the default CRT-Params for 64-bit integers
     * @return CRT-pramams for 64-bit integers
     */
    public static CRTParams getDefault64BitParams() {
        return generateParams(default64BitParams, 13);
    }

    /**
     * Generates a new EC-ElGamal key-pair
     * @param params the crt-params to attach
     * @return the newly generated key
     */
    public static ECElGamalKey generateNewKey(CRTParams params) {
        return new ECElGamalKey(generateKey(), params);
    }

    /**
     * Computes the ECElGamalKey based on an encoded key and the CRT-params to attach.
     * @param encodedKey an encoded version of the ECElGamalKey
     * @param params the global CRT-Params
     * @return an ECElGamalKey instance
     */
    public static ECElGamalKey restoreKey(byte[] encodedKey, CRTParams params) {
        return new ECElGamalKey(encodedKey, params);
    }

    /**
     * Encrypts an integer with homomorphic EC-ElGamal
     * @param integer the integer to encrypt (!pay attention to the bit limits from the CRT-Params!)
     * @param key the ECElGamalKey key
     * @return the encrypted integer
     */
    public static ECElGamalCiphertext encrypt(BigInteger integer, ECElGamalKey key) {
        byte[][] ciphertexts = new byte[key.params.ds.length][];
        for(int iter=0; iter<ciphertexts.length; iter++) {
            BigInteger mi = integer.mod(key.getParams().ds[iter]);
            ciphertexts[iter] = encrypt(mi.longValue(), key.keyContent);
        }
        return new ECElGamalCiphertext(ciphertexts);
    }

    /**
     * Decrypts an ECElGamalCiphertext and returns the plaintext integer.
     * !Does not return negative numbers, If needed use decrypt32, decrypt64 instead for int and long!
     * @param ciphertext the EC-ElGamal ciphertext
     * @param key the the EC-ElGamal key
     * @return the positive plaintext value as an BigInteger
     */
    public static BigInteger decrypt(ECElGamalCiphertext ciphertext, ECElGamalKey key) {
        BigInteger[] subMessages = new BigInteger[ciphertext.getNumPartitions()];
        for(int iter=0; iter<subMessages.length; iter++) {
            subMessages[iter] = BigInteger.valueOf(decrypt(ciphertext.ciphertexts[iter], key.keyContent, true));
        }
        return solveCRT(subMessages, key.params.ds, key.params.d);
    }

    /**
     * Decrypts an ECElGamalCiphertext and returns the plaintext integer of type int.
     * Supports also negative integers.
     * @param ciphertext the EC-ElGamal ciphertext
     * @param key the the EC-ElGamal key
     * @return the plaintext value of type int
     */
    public static int decrypt32(ECElGamalCiphertext ciphertext, ECElGamalKey key) {
        BigInteger res = decrypt(ciphertext, key);
        if (res.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) > 0) {
            return res.subtract(key.getParams().d).intValue();
        }
        return res.intValue();
    }

    /**
     * Decrypts an ECElGamalCiphertext and returns the plaintext integer of type long.
     * Supports also negative integers.
     * @param ciphertext the EC-ElGamal ciphertext
     * @param key the the EC-ElGamal key
     * @return the plaintext value of type long
     */
    public static long decrypt64(ECElGamalCiphertext ciphertext, ECElGamalKey key) {
        BigInteger res = decrypt(ciphertext, key);
        if (res.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) > 0) {
            return res.subtract(key.getParams().d).longValue();
        }
        return res.longValue();
    }

    /**
     * Adds two EC-El-Gamal ciphertexts and outputs the resulting ciphertext.
     * @param c1 first ciphertext
     * @param c2 second ciphertext
     * @return the resulting ciphertext of the addition
     */
    public static ECElGamalCiphertext add(ECElGamalCiphertext c1, ECElGamalCiphertext c2) {
        byte[][] result = new byte[c1.getNumPartitions()][];
        for(int iter=0; iter<result.length; iter++) {
            result[iter] = homAdd(c1.ciphertexts[iter], c2.ciphertexts[iter]);
        }
        return new ECElGamalCiphertext(result);
    }


    //native functions
    private static native int initEcElGamal(int group_id);
    private static native int deinitECElGamal();
    private static native byte[] generateKey();
    private static native byte[] encrypt(long value, byte[] key_oct);
    private static native long decrypt(byte[] ciphertext_oct, byte[] key_oct, boolean use_bsgs);
    private static native byte[] homAdd(byte[] ciphertext_1_oct, byte[] ciphertext_2_oct);

    /**
     * Initializes a BSGS table for the decryption
     * (optional) default size 2^16.
     * @param table_size the number of table entries
     * @return 0 ok -1 error
     */
    public static native int initBsgsTable(int table_size);
    private static native int getPointSize();

    public static class ECElGamalCiphertext {
        private byte[][] ciphertexts;

        ECElGamalCiphertext(byte[][] ciphertexts) {
            this.ciphertexts = ciphertexts;
        }

        public int getNumPartitions() {
            return ciphertexts.length;
        }

        public int getEncodedSize() {
            int len = 0;
            for (byte[] data : ciphertexts)
                len += data.length;
            return len;
        }

        public byte[] encode(){
            int lenPoint, curpos = 0;
            byte[] result = new byte[getEncodedSize()];
            lenPoint = getPointSize();
            for (byte[] data : ciphertexts) {
                System.arraycopy(data, 0, result, curpos, data.length);
                curpos += data.length;
                assert data.length == lenPoint*2;
            }
            return result;
        }

        public static ECElGamalCiphertext decode(byte[] encodedCiphertext) {
            byte[][] ciphertexts;
            int numPartitions, pointSize;
            pointSize = getPointSize() * 2;
            numPartitions = encodedCiphertext.length / pointSize;
            ciphertexts = new byte[numPartitions][];
            for (int iter=0; iter<numPartitions; iter++) {
                ciphertexts[iter] = new byte[pointSize];
                System.arraycopy(encodedCiphertext, iter*pointSize, ciphertexts[iter], 0, pointSize);
            }
            return new ECElGamalCiphertext(ciphertexts);
        }

        public ECElGamalCiphertext copy() {
            byte[][] ciphertextsCopy = new byte[ciphertexts.length][];
            for (int i=0; i<ciphertexts.length; i++) {
                ciphertextsCopy[i] = Arrays.copyOf(ciphertexts[i], ciphertexts[i].length);
            }
            return new ECElGamalCiphertext(ciphertextsCopy);
        }
    }

    public static final class CRTParams {
        private final BigInteger[] ds;
        private final BigInteger d;
        private final int numbits;

        public CRTParams(BigInteger[] ds, BigInteger d, int numbits) {
            this.ds = ds;
            this.d = d;
            this.numbits = numbits;
        }

        public BigInteger getD() {
            return d;
        }

        public int getNumbits() {
            return numbits;
        }

        public int getNumPartitions() {
            return ds.length;
        }

        public String getStringRep() {
            StringBuilder sb = new StringBuilder();
            String delim = "|";
            sb.append(numbits)
                    .append(delim)
                    .append(d).append(delim);
            for(BigInteger b : ds)
                sb.append(b.toString()).append(delim);
            sb.setLength(sb.length()-1);
            return sb.toString();
        }

        public static CRTParams fromStringRep(String rep) {
            String delim = "\\|";
            String[] splits = rep.split(delim);
            int numbits = Integer.valueOf(splits[0]);
            BigInteger d = new BigInteger(splits[1]);
            int numDs = splits.length-2;
            BigInteger[] ds = new BigInteger[numDs];
            for(int iter=0;iter<numDs;iter++) {
                ds[iter] = new BigInteger(splits[2+iter]);
            }
            return new CRTParams(ds, d, numbits);
        }

    }

    public static class ECElGamalKey implements Key {
        private CRTParams params;
        private boolean isPublic;
        private byte[] keyContent;

        ECElGamalKey(byte[] key, CRTParams params) {
            this.params = params;
            this.isPublic = key[0] != 0;
            this.keyContent = key;

        }

        public CRTParams getParams() {
            return params;
        }

        public boolean isPublic() {
            return isPublic;
        }

        @Override
        public String getAlgorithm() {
            return null;
        }

        @Override
        public String getFormat() {
            return "EC-ElGamal";
        }

        @Override
        public byte[] getEncoded() {
            return keyContent.clone();
        }
    }



}
