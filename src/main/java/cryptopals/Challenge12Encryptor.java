package cryptopals;

import cryptopals.ciphers.Aes128EcbPkcs7Cipher;

import java.security.SecureRandom;

public class Challenge12Encryptor implements ConsistentKeyEncryptor {

    private final byte[] key = new byte[Utils.AES_128_BLOCK_SIZE_IN_BYTES];
    private final Aes128EcbPkcs7Cipher aes128EcbPkcs7Cipher;
    private final byte[] appendedBytes;

    public Challenge12Encryptor(Aes128EcbPkcs7Cipher aes128EcbPkcs7Cipher, byte[] appendedBytes) {
        this.aes128EcbPkcs7Cipher = aes128EcbPkcs7Cipher;
        new SecureRandom().nextBytes(key);
        this.appendedBytes = appendedBytes;
    }

    @Override
    public byte[] encrypt(byte[] input) {
        return encrypt(input, input.length);
    }

    @Override
    public byte[] encrypt(byte[] input, int inputLen) {
        if (input.length < inputLen) {
            throw new IllegalArgumentException("Incorrect input length");
        }
        var newInput = appendFixedText(input, inputLen);

        return aes128EcbPkcs7Cipher.encrypt(newInput, key);
    }

    private byte[] appendFixedText(byte[] input, int inputLen) {
        if (inputLen == 0) {
            return appendedBytes;
        }
        var output = new byte[inputLen + appendedBytes.length];
        System.arraycopy(input, 0, output, 0, inputLen);
        System.arraycopy(appendedBytes, 0, output, inputLen, appendedBytes.length);
        return output;
    }
}
