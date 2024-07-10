package cryptopals;

import cryptopals.ciphers.Aes128CbcPkcs7Cipher;
import cryptopals.ciphers.Aes128EcbPkcs7Cipher;
import lombok.RequiredArgsConstructor;

import java.util.Map;
import java.util.Random;

import static java.util.Map.entry;

@RequiredArgsConstructor
public class Challenge11EncryptEcbOrCbc {

    private final Aes128EcbPkcs7Cipher aes128EcbPkcs7Cipher;
    private final Aes128CbcPkcs7Cipher aes128CbcPkcs7Cipher;

    private static final Random random = Utils.SECURE_RANDOM;

    public Map.Entry<String, byte[]> encryptEcbOrCbc(byte[] input) {
        var newInput = prependAndAppendBytes(input);

        var key = randomByteArray(Utils.AES_128_BLOCK_SIZE_IN_BYTES);
        if (random.nextBoolean()) {
            return entry("ECB", aes128EcbPkcs7Cipher.encrypt(newInput, key));
        } else {
            var iv = randomByteArray(Utils.AES_128_BLOCK_SIZE_IN_BYTES);
            return entry("CBC", aes128CbcPkcs7Cipher.encrypt(newInput, iv, key));
        }
    }

    private byte[] prependAndAppendBytes(byte[] input) {
        var prependBytes = random.nextInt(5, 11);
        var appendBytes = random.nextInt(5, 11);

        var newInput = new byte[input.length + prependBytes + appendBytes];

        var addedBytes = new byte[10];
        random.nextBytes(addedBytes);
        System.arraycopy(addedBytes, 0, newInput, 0, prependBytes);

        System.arraycopy(input, 0, newInput, prependBytes, input.length);


        random.nextBytes(addedBytes);
        System.arraycopy(addedBytes, 0, newInput, prependBytes + input.length, appendBytes);

        return newInput;
    }

    private byte[] randomByteArray(int len) {
        var out = new byte[len];
        random.nextBytes(out);
        return out;
    }
}
