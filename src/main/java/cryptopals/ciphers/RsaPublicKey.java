package cryptopals.ciphers;

import java.math.BigInteger;

public record RsaPublicKey (
        BigInteger e, BigInteger n
) implements RsaKey {
    @Override
    public BigInteger getExponent() {
        return e;
    }

    @Override
    public BigInteger getModulus() {
        return n;
    }
}
