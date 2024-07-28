package cryptopals.ciphers;

import java.math.BigInteger;

public interface RsaKey {

    BigInteger getExponent();
    BigInteger getModulus();

}
