package cryptopals.ciphers;

import cryptopals.Utils;

import java.math.BigInteger;

public class RsaCipher {

    public static RsaPrivateKey generatePrivateKey(int bitLength) {
        var e = BigInteger.valueOf(3);

        BigInteger p = generatePrime(bitLength, e);
        BigInteger q = generatePrime(bitLength, e);

        var n = p.multiply(q);

        BigInteger pm1 = p.subtract(BigInteger.ONE);
        BigInteger qm1 = q.subtract(BigInteger.ONE);
        var et = pm1.multiply(qm1);

        var d = e.modInverse(et);

        return new RsaPrivateKey(p, q, e, d, n);
    }

    private static BigInteger generatePrime(int bitLength, BigInteger e) {
        BigInteger prime;
        do {
            prime = BigInteger.probablePrime(bitLength / 2, Utils.SECURE_RANDOM);

            //e must be coprime both to (p-1) and (q-1) to be coprime invertible modulus (p-1)*(q-1)
        } while (!e.gcd(prime.subtract(BigInteger.ONE)).equals(BigInteger.ONE));
        return prime;
    }

    public static RsaPublicKey generatePublicKey(RsaPrivateKey privateKey) {
        return new RsaPublicKey(privateKey.e(), privateKey.n());
    }

    public byte[] apply(byte[] input, RsaKey key) {
        var m = new BigInteger(input);
        if (m.compareTo(key.getModulus()) >= 0) {
            throw new IllegalArgumentException("Message is greater than modulus");
        }

        var c = m.modPow(key.getExponent(), key.getModulus());

        return c.toByteArray();
    }
}
