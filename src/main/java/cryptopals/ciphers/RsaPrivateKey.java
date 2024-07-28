package cryptopals.ciphers;

import java.math.BigInteger;


public record RsaPrivateKey (
        BigInteger p,
        BigInteger q,
        BigInteger e,
        BigInteger d,
        BigInteger n
) implements RsaKey{
    @Override
    public BigInteger getExponent() {
        return d;
    }

    @Override
    public BigInteger getModulus() {
        return n;
    }
}
