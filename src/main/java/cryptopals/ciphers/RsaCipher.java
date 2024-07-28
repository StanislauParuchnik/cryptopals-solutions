package cryptopals.ciphers;

import cryptopals.Utils;

import java.math.BigInteger;

public class RsaCipher {

    public static RsaPrivateKey generatePrivateKey(int bitLength) {
        var e = BigInteger.valueOf(3);

        BigInteger p;
        BigInteger q;

        BigInteger pm1;
        BigInteger qm1;

        while (true) {
            p = BigInteger.probablePrime(bitLength / 2, Utils.SECURE_RANDOM);
            q = BigInteger.probablePrime(bitLength / 2, Utils.SECURE_RANDOM);

            pm1 = p.subtract(BigInteger.ONE);
            qm1 = q.subtract(BigInteger.ONE);

            //e must be coprime both to  (p-1) and (q-1) to be coprime invertible modulus (p-1)*(q-1)
            if (e.gcd(pm1).equals(BigInteger.ONE) && e.gcd(qm1).equals(BigInteger.ONE)) {
                break;
            }
        }


        var n = p.multiply(q);

        var et = (pm1).multiply(qm1);

        var d = e.modInverse(et);

        return new RsaPrivateKey(p, q, e, d, n);
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
