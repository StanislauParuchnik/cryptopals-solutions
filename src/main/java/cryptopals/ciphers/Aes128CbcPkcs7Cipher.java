package cryptopals.ciphers;

import cryptopals.PKCS7Padder;
import cryptopals.Utils;

import static cryptopals.Utils.AES_128_BLOCK_SIZE_IN_BYTES;

public class Aes128CbcPkcs7Cipher {

    private final Aes128EcbNoPaddingCipher aes128EcbNoPaddingCipher = new Aes128EcbNoPaddingCipher();

    public byte[] encrypt(byte[] input, byte[] iv, byte[] key) {
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("Input can't be null or empty");
        }
        Utils.validateBlockLength(iv, "Init vector");
        Utils.validateBlockLength(key, "Key");

        var encryptedSize = (input.length / AES_128_BLOCK_SIZE_IN_BYTES + 1) * AES_128_BLOCK_SIZE_IN_BYTES;
        var encrypted = new byte[encryptedSize];

        int blockNumber = 0;
        byte[] previousCipherText = iv;
        int previousCipherTextOffset = 0;
        byte[] block = new byte[AES_128_BLOCK_SIZE_IN_BYTES];
        while ((blockNumber + 1) * AES_128_BLOCK_SIZE_IN_BYTES <= input.length) {
            fillCbcBlockToEncrypt(input, blockNumber * AES_128_BLOCK_SIZE_IN_BYTES,
                    previousCipherText, previousCipherTextOffset,
                    block);

            aes128EcbNoPaddingCipher.encrypt(block, key, 0, AES_128_BLOCK_SIZE_IN_BYTES,
                    encrypted, blockNumber * AES_128_BLOCK_SIZE_IN_BYTES);

            previousCipherText = encrypted;
            previousCipherTextOffset = blockNumber * AES_128_BLOCK_SIZE_IN_BYTES;
            blockNumber++;
        }


        if (encryptedSize - input.length == AES_128_BLOCK_SIZE_IN_BYTES) {
            PKCS7Padder.padEmptyBlock(block, 0, AES_128_BLOCK_SIZE_IN_BYTES);
        } else {
            PKCS7Padder.padBlock(input,
                    blockNumber * AES_128_BLOCK_SIZE_IN_BYTES,
                    block,
                    0,
                    AES_128_BLOCK_SIZE_IN_BYTES
            );
        }
        fillCbcBlockToEncrypt(block, 0,
                previousCipherText, previousCipherTextOffset,
                block);

        aes128EcbNoPaddingCipher.encrypt(block, key, 0, AES_128_BLOCK_SIZE_IN_BYTES,
                encrypted, blockNumber * AES_128_BLOCK_SIZE_IN_BYTES);


        return encrypted;
    }

    private void fillCbcBlockToEncrypt(byte[] plainText, int plainTextOffset,
                                       byte[] previousCipherText, int previousCipherTextOffset,
                                       byte[] output) {
        Utils.xor(plainText, plainTextOffset,
                previousCipherText, previousCipherTextOffset,
                output, 0,
                output.length);
    }

    public byte[] decrypt(byte[] encrypted, byte[] iv, byte[] key) {
        if (encrypted == null) {
            throw new IllegalArgumentException("encrypted can't be null");
        }
        return decrypt(encrypted, encrypted.length, iv, key);
    }

    public byte[] decrypt(byte[] encrypted, int length, byte[] iv, byte[] key) {
        if (encrypted == null) {
            throw new IllegalArgumentException("encrypted can't be null");
        }
        if (encrypted.length < length) {
            throw new IllegalArgumentException("encrypted buffer is shorter than " + length);
        }
        if (length % AES_128_BLOCK_SIZE_IN_BYTES != 0) {
            throw new IllegalArgumentException("encrypted length is incorrect");
        }
        Utils.validateBlockLength(iv, "Init vector");
        Utils.validateBlockLength(key, "Key");

        int blockNumber = 0;
        byte[] decrypted = new byte[length];
        byte[] previousCipherText = iv;
        int previousCipherTextOffset = 0;
        int offset;
        while ((offset = blockNumber * AES_128_BLOCK_SIZE_IN_BYTES) < length) {
            aes128EcbNoPaddingCipher.decrypt(encrypted, key,
                    offset, AES_128_BLOCK_SIZE_IN_BYTES,
                    decrypted, offset);

            applyCbcDecryption(decrypted, offset, previousCipherText, previousCipherTextOffset);

            previousCipherText = encrypted;
            previousCipherTextOffset = blockNumber * AES_128_BLOCK_SIZE_IN_BYTES;
            blockNumber++;
        }

        return PKCS7Padder.unPadBuffer(decrypted, AES_128_BLOCK_SIZE_IN_BYTES);
    }

    private void applyCbcDecryption(byte[] decrypted, int decryptedOffset,
                                    byte[] previousCipherText, int previousCipherTextOffset) {
        Utils.xor(decrypted, decryptedOffset,
                previousCipherText, previousCipherTextOffset,
                decrypted, decryptedOffset,
                AES_128_BLOCK_SIZE_IN_BYTES);
    }
}
