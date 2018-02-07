# EC-ElGamal

This repository contains a C implementation of the additive homomorphic elliptic curve based EL-Gamal cryptographic scheme and a corresponding Java JNI wrapper. The elliptic curve operations of OpenSSL are used for the implementation.
Ciphertexts can be added toghether such that the decrypted result corresponds to the sum of the plaintexts (i.e. p1 + p2 = Dec(Enc(p1) ++ Enc(p2))))

## Content 
The *native* folder contains the C implementation of the scheme and the *src* folder contains the Java wrapper library.

### C Library
The C library contains two versions of EC-Elgamal, a basic version and a Chinese Remainder Thereom (CRT) based optimized version. The library builds with cmake. To compile the library and run the benchmark run: 
Note that OpenSSL is required!

```
cd native
cmake .
make
./out/ecelgamal
```

### Java Wrapper
The Java library wraps the CRT based EC-ElGamal scheme implemented in C in a Java class with the JNI. The Java wrapper contains a prebuilt version of the library for linux64 and darwin64 (src/main/resources).
To build the jar package, maven is required. The following command builds the library:

```
mvn package
```
Here an example on how to use the library.
```java
ECElGamal.CRTParams params32 = ECElGamal.getDefault32BitParams();
ECElGamal.ECElGamalKey key32 = ECElGamal.generateNewKey(params32)
ECElGamal.ECElGamalCiphertext cipher1,cipher2;
int val1 = 2, val2 = -3;
cipher1 = ECElGamal.encrypt(BigInteger.valueOf(val1), key32);
cipher2 = ECElGamal.encrypt(BigInteger.valueOf(val2), key32);
cipher1 = ECElGamal.add(cipher1, cipher2);
int decriptedVal = ECElGamal.decrypt32(cipher1, key32);
assertEquals(val1 + val2, decriptedVal);
```

## Performance 
On a 192-bit curve and with an EC2 micro instance in ms.
 ```
Plain EC-ElGamal 32-bit integers
Avg ENC Time 0.514724 Avg DEC Time 545.581

CRT optimized EC-ElGamal 32-bit integers
Avg ENC Time 0.964643 Avg DEC Time 0.556396

CRT optimized EC-ElGamal 64-bit integers
Avg ENC Time 1.44365 Avg DEC Time 1.75101
```

## Security
This library is for academic purposes, gives no security guarantees and may contain implementation vulnerabilities.
