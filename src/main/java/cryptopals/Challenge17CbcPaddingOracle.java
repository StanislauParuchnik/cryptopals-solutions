package cryptopals;

import cryptopals.ciphers.Aes128CbcPkcs7Cipher;
import cryptopals.exceptions.InvalidPaddingException;

public class Challenge17CbcPaddingOracle implements PaddingOracle {

    private final byte[] key;
    private final Aes128CbcPkcs7Cipher aes128CbcPkcs7Cipher;

    public Challenge17CbcPaddingOracle(Aes128CbcPkcs7Cipher aes128CbcPkcs7Cipher) {
        this.aes128CbcPkcs7Cipher = aes128CbcPkcs7Cipher;
        this.key = Utils.randomBytes(Utils.AES_128_BLOCK_SIZE_IN_BYTES);
    }


    @Override
    public boolean isPaddingCorrect(byte[] iv, byte[] encrypted, int length) {
        try {
            aes128CbcPkcs7Cipher.decrypt(encrypted, length, iv, key);
            return true;
        } catch (InvalidPaddingException e) {
            return false;
        }
    }

    public byte[] encrypt(byte[] plainText, byte[] iv) {
        return aes128CbcPkcs7Cipher.encrypt(plainText, iv, key);
    }
}
