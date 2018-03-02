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

import ch.ethz.dsg.ecelgamal.ECElGamal;
import org.junit.*;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import static junit.framework.TestCase.assertEquals;

public class ECElGamalTest {

    private ECElGamal.CRTParams params32 = ECElGamal.getDefault32BitParams();
    private ECElGamal.CRTParams params64 = ECElGamal.getDefault64BitParams();
    ECElGamal.ECElGamalKey key32 = ECElGamal.generateNewKey(params32);
    ECElGamal.ECElGamalKey key64 = ECElGamal.generateNewKey(params64);

    Random rand = new Random();

    @BeforeClass
    public static void init() {
            ECElGamal.initBsgsTable(1 << 14);
    }

    @AfterClass
    public static void deinit() {
    }

    @Test
    public void simple() {
        int val = 0;
        ECElGamal.ECElGamalCiphertext cipher = ECElGamal.encrypt(BigInteger.valueOf(val), key32);
        int decriptedVal = ECElGamal.decrypt32(cipher, key32);
        assertEquals(decriptedVal, val);
    }

    @Test
    public void simpleAdd() {
        ECElGamal.ECElGamalCiphertext cipher1,cipher2;
        int val1 = 2, val2 = -3;
        cipher1 = ECElGamal.encrypt(BigInteger.valueOf(val1), key32);
        cipher2 = ECElGamal.encrypt(BigInteger.valueOf(val2), key32);
        cipher1 = ECElGamal.add(cipher1, cipher2);
        int decriptedVal = ECElGamal.decrypt32(cipher1, key32);
        assertEquals(val1 + val2, decriptedVal);
    }

    @Test
    public void randTestInt() {
        int val1, val2;
        for (int i=0; i<100; i++) {
            val1 = rand.nextInt()/2;
            val2 = rand.nextInt()/2;

            ECElGamal.ECElGamalCiphertext cipher1, cipher2;

            cipher1 = ECElGamal.encrypt(BigInteger.valueOf(val1), key32);
            cipher2 = ECElGamal.encrypt(BigInteger.valueOf(val2), key32);
            cipher1 = ECElGamal.add(cipher1, cipher2);
            int decriptedVal = ECElGamal.decrypt32(cipher1, key32);
            assertEquals(val1 + val2, decriptedVal);
            System.out.println("ok " + i);
        }
    }

    @Test
    public void randTestLong() {
        long val1, val2;
        for (int i=0; i<100; i++) {
            val1 = rand.nextLong()/2;
            val2 = rand.nextLong()/2;

            ECElGamal.ECElGamalCiphertext cipher1, cipher2;

            cipher1 = ECElGamal.encrypt(BigInteger.valueOf(val1), key64);
            cipher2 = ECElGamal.encrypt(BigInteger.valueOf(val2), key64);
            cipher1 = ECElGamal.add(cipher1, cipher2);
            long decriptedVal = ECElGamal.decrypt64(cipher1, key64);
            assertEquals(val1 + val2, decriptedVal);
            System.out.println("ok " + i);
        }
    }



    private static double convertMS(long val) {
        return ((double) val) / 1000000.0;
    }

    @Test
    public void measureTime() {
        long val1, val2, timeadd;
        int add = 10;
        for (int i=0; i<100; i++) {
            val1 = rand.nextLong()/10000;
            val2 = rand.nextLong()/10000;

            ECElGamal.ECElGamalCiphertext cipher1, cipher2;

            long encrypt = System.nanoTime();
            cipher1 = ECElGamal.encrypt(BigInteger.valueOf(val1), key64);
            encrypt = System.nanoTime() - encrypt;

            cipher2 = ECElGamal.encrypt(BigInteger.valueOf(val2), key64);
            long addTime = System.nanoTime();
            for(int it=0; it<add; it++) {
                cipher1 = ECElGamal.add(cipher1, cipher2);
            }
            addTime =  (System.nanoTime() - addTime) / add;

            long decrypt = System.nanoTime();
            long decriptedVal = ECElGamal.decrypt64(cipher1, key64);
            decrypt = System.nanoTime() - decrypt;
            assertEquals(val1 + add * val2, decriptedVal);
            System.out.println(String.format("Enc: %.2f, Dec: %.2f Avg Add: %.2f", convertMS(encrypt), convertMS(decrypt), convertMS(addTime)));
        }
    }


    @Test
    public void encodeDecode() {
        int val = 10;
        ECElGamal.ECElGamalCiphertext cipher = ECElGamal.encrypt(BigInteger.valueOf(val), key32);
        byte[] encode = cipher.encode();
        ECElGamal.ECElGamalCiphertext cipherAfter = ECElGamal.ECElGamalCiphertext.decode(encode);
        int decriptedVal = ECElGamal.decrypt32(cipherAfter, key32);
        assertEquals(decriptedVal, val);
    }

    @Test
    public void paramsPrint() {
        ECElGamal.CRTParams params = ECElGamal.generateCRTParams(new SecureRandom(), 13, 5);
        System.out.println(params.getStringRep());
    }


}
