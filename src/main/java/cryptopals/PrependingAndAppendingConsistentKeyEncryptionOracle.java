package cryptopals;

import cryptopals.ciphers.Aes128EcbPkcs7Cipher;

import java.security.SecureRandom;

public class PrependingAndAppendingConsistentKeyEncryptionOracle implements ConsistentKeyEncryptionOracle {

    private final byte[] key = new byte[Utils.AES_128_BLOCK_SIZE_IN_BYTES];
    private final Aes128EcbPkcs7Cipher aes128EcbPkcs7Cipher;
    private final byte[] appendedBytes;
    private final byte[] prependedBytes;

    public PrependingAndAppendingConsistentKeyEncryptionOracle(Aes128EcbPkcs7Cipher aes128EcbPkcs7Cipher, byte[] appendedBytes,
                                                               int prependedBytesNumber) {
        this.aes128EcbPkcs7Cipher = aes128EcbPkcs7Cipher;
        var random = new SecureRandom();
        random.nextBytes(key);
        this.appendedBytes = appendedBytes;
        this.prependedBytes = new byte[prependedBytesNumber];
        random.nextBytes(prependedBytes);
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
        var newInput = prependAndAppendData(input, inputLen);

        return aes128EcbPkcs7Cipher.encrypt(newInput, key);
    }

    private byte[] prependAndAppendData(byte[] input, int inputLen) {
        var output = new byte[prependedBytes.length + inputLen + appendedBytes.length];

        System.arraycopy(prependedBytes, 0, output, 0, prependedBytes.length);
        if (inputLen != 0) {
            System.arraycopy(input, 0, output, prependedBytes.length, inputLen);
        }
        System.arraycopy(appendedBytes, 0, output, prependedBytes.length + inputLen, appendedBytes.length);

        return output;
    }
}
