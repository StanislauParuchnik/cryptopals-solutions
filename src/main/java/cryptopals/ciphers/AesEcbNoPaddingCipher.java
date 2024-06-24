package cryptopals.ciphers;

import cryptopals.CryptoException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AesEcbNoPaddingCipher {

    public static void encrypt(byte[] input, byte[] key, int inputOffset, int inputLen,
                                 byte[] output, int outputOffset) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            Cipher cipherAes = Cipher.getInstance("AES/ECB/NoPadding");
            cipherAes.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            cipherAes.doFinal(input, inputOffset, inputLen, output, outputOffset);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    public static byte[] decrypt(byte[] encrypted, byte[] key) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

            Cipher cipherAes = Cipher.getInstance("AES/ECB/NoPadding");
            cipherAes.init(Cipher.DECRYPT_MODE, secretKeySpec);
            return cipherAes.doFinal(encrypted);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    public static void decrypt(byte[] input, byte[] key, int inputOffset, int inputLen,
                               byte[] output, int outputOffset) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            Cipher cipherAes = Cipher.getInstance("AES/ECB/NoPadding");
            cipherAes.init(Cipher.DECRYPT_MODE, secretKeySpec);
            cipherAes.doFinal(input, inputOffset, inputLen, output, outputOffset);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }


}
