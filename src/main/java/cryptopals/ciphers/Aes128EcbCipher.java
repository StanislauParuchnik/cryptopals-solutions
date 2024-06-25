package cryptopals.ciphers;

import cryptopals.CryptoException;
import lombok.RequiredArgsConstructor;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

@RequiredArgsConstructor
public abstract class Aes128EcbCipher {
    protected final String padding;

    public byte[] encrypt(byte[] input, byte[] key) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            Cipher cipherAes = Cipher.getInstance("AES/ECB/" + padding);
            cipherAes.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            return cipherAes.doFinal(input);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    public void encrypt(byte[] input, byte[] key, int inputOffset, int inputLen,
                               byte[] output, int outputOffset) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            Cipher cipherAes = Cipher.getInstance("AES/ECB/" + padding);
            cipherAes.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            cipherAes.doFinal(input, inputOffset, inputLen, output, outputOffset);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    public byte[] decrypt(byte[] encrypted, byte[] key) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

            Cipher cipherAes = Cipher.getInstance("AES/ECB/" + padding);
            cipherAes.init(Cipher.DECRYPT_MODE, secretKeySpec);
            return cipherAes.doFinal(encrypted);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    public void decrypt(byte[] input, byte[] key, int inputOffset, int inputLen,
                               byte[] output, int outputOffset) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            Cipher cipherAes = Cipher.getInstance("AES/ECB/" + padding);
            cipherAes.init(Cipher.DECRYPT_MODE, secretKeySpec);
            cipherAes.doFinal(input, inputOffset, inputLen, output, outputOffset);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }
}
