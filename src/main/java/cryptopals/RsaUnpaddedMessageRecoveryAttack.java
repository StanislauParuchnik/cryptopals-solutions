package cryptopals;

import cryptopals.ciphers.RsaPublicKey;
import lombok.RequiredArgsConstructor;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

@RequiredArgsConstructor
public class RsaUnpaddedMessageRecoveryAttack {

    private final OneTimeRsaDecryptor oneTimeRsaDecryptor;


    public byte[] bypassOneTimeDecryption(byte[] encrypted, RsaPublicKey publicKey) throws NoSuchAlgorithmException {
        var s = BigInteger.TWO;

        //C' = ((S**E mod N) C) mod N
        var modifiedEncrypted = (s.modPow(publicKey.e(), publicKey.n()))
                .multiply(new BigInteger(encrypted)).mod(publicKey.n())
                .toByteArray();

        var modifiedDecrypted = oneTimeRsaDecryptor.decrypt(modifiedEncrypted);

        //          P'
        //    P = -----  mod N
        //          S
        return new BigInteger(modifiedDecrypted).multiply(s.modInverse(publicKey.n())).mod(publicKey.n()).toByteArray();
    }
}
