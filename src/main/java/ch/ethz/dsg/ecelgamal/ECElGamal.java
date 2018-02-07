package ch.ethz.dsg.ecelgamal;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.util.HashSet;
import java.util.Random;

import org.scijava.nativelib.NativeLibraryUtil;
import org.scijava.nativelib.NativeLoader;

public class ECElGamal {

    public static int NID_X9_62_prime192v1 = 409;
    public static int NID_X9_62_prime239v1 = 412;
    public static int NID_X9_62_prime256v1 = 415;

    private static long[] default32BitParams = {119963L, 103997L};
    private static long[] default64BitParams = {3624683L, 3356513L, 3315317L};

    static {
        try {
            NativeLibraryUtil.loadNativeLibrary(ECElGamal.class, "ecelgamal-jni-wrapper");
        } catch (Exception e) {
            e.printStackTrace();
        }

        /*try {
            NativeUtils.loadLibraryFromJar("/lib/osx_64/libecelgamal-jni-wrapper.dylib");
        } catch (IOException e) {
            try {
                NativeUtils.loadLibraryFromJar("/libecelgamal-jni-wrapper.so");
            } catch (IOException e1) {
                e1.printStackTrace();
            }
        }*/
        initEcElGamal(NID_X9_62_prime192v1);
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

    public static CRTParams getDefault32BitParams() {
        return generateParams(default32BitParams, 17);
    }

    public static CRTParams getDefault64BitParams() {
        return generateParams(default64BitParams, 22);
    }


    public static ECElGamalKey generateNewKey(CRTParams params) {
        return new ECElGamalKey(generateKey(), params);
    }

    public static ECElGamalKey restoreKey(byte[] encodedKey, CRTParams params) {
        return new ECElGamalKey(encodedKey, params);
    }

    public static ECElGamalCiphertext encrypt(BigInteger integer, ECElGamalKey key) {
        byte[][] ciphertexts = new byte[key.params.ds.length][];
        for(int iter=0; iter<ciphertexts.length; iter++) {
            BigInteger mi = integer.mod(key.getParams().ds[iter]);
            ciphertexts[iter] = encrypt(mi.longValue(), key.keyContent);
        }
        return new ECElGamalCiphertext(ciphertexts);
    }

    public static BigInteger decrypt(ECElGamalCiphertext ciphertext, ECElGamalKey key) {
        BigInteger[] subMessages = new BigInteger[ciphertext.getNumPartitions()];
        for(int iter=0; iter<subMessages.length; iter++) {
            subMessages[iter] = BigInteger.valueOf(decrypt(ciphertext.ciphertexts[iter], key.keyContent, true));
        }
        return solveCRT(subMessages, key.params.ds, key.params.d);
    }

    public static int decrypt32(ECElGamalCiphertext ciphertext, ECElGamalKey key) {
        BigInteger res = decrypt(ciphertext, key);
        if (res.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) > 0) {
            return res.subtract(key.getParams().d).intValue();
        }
        return res.intValue();
    }

    public static long decrypt64(ECElGamalCiphertext ciphertext, ECElGamalKey key) {
        BigInteger res = decrypt(ciphertext, key);
        if (res.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) > 0) {
            return res.subtract(key.getParams().d).longValue();
        }
        return res.longValue();
    }

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
