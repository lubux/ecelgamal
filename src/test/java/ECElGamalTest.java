import ch.ethz.dsg.ecelgamal.ECElGamal;
import org.junit.*;

import java.math.BigInteger;
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
            ECElGamal.initBsgsTable(1 << 16);
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

    @Test
    public void encodeDecode() {
        int val = 10;
        ECElGamal.ECElGamalCiphertext cipher = ECElGamal.encrypt(BigInteger.valueOf(val), key32);
        byte[] encode = cipher.encode();
        ECElGamal.ECElGamalCiphertext cipherAfter = ECElGamal.ECElGamalCiphertext.decode(encode);
        int decriptedVal = ECElGamal.decrypt32(cipherAfter, key32);
        assertEquals(decriptedVal, val);
    }

}
