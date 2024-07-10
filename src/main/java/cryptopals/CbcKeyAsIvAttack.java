package cryptopals;

import cryptopals.ciphers.Aes128CbcPkcs7Cipher;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

@Slf4j
public class CbcKeyAsIvAttack {
    private final Aes128CbcPkcs7Cipher aes128CbcPkcs7Cipher;
    private final byte[] key;


    public CbcKeyAsIvAttack(Aes128CbcPkcs7Cipher aes128CbcPkcs7Cipher, byte[] key) {
        this.aes128CbcPkcs7Cipher = aes128CbcPkcs7Cipher;
        this.key = key;
    }

    public byte[] encrypt(String str) {
        return aes128CbcPkcs7Cipher.encrypt(str.getBytes(StandardCharsets.UTF_8), key, key);
    }

    void decrypt(byte[] encrypted) {
        var decryptedBytes = aes128CbcPkcs7Cipher.decrypt(encrypted, key, key);
        if (!Utils.isASCII(decryptedBytes)) {
            //todo as exercise use UTF to pass decrypted String. Things are complicated with it considering
            // Java's strings compactification and the fact the UTF replaces invalid characters with replacement
            // characters while building String from byte[]. For now just pass it so that it can be easily reverted
            // to originalc bytes back.
            throw new RuntimeException("ASCII non-compliant string: " + Base64.getEncoder().encodeToString(decryptedBytes));
        }
    }


    public byte[] extractIV(byte[] encrypted) {
        if (encrypted.length < 3 * Utils.AES_128_BLOCK_SIZE_IN_BYTES) {
            throw new IllegalArgumentException("Impossible to restore key: ciphertext too short (" +
                    encrypted.length + " < " + 3 * Utils.AES_128_BLOCK_SIZE_IN_BYTES + ")");
        }

        var modifiedCiphertext = Arrays.copyOf(encrypted, encrypted.length);
        //C_1, C_2, C_3 -> C_1, 0, C_1
        Arrays.fill(modifiedCiphertext, Utils.AES_128_BLOCK_SIZE_IN_BYTES, Utils.AES_128_BLOCK_SIZE_IN_BYTES * 2, (byte) 0);
        System.arraycopy(encrypted, 0,
                modifiedCiphertext, Utils.AES_128_BLOCK_SIZE_IN_BYTES * 2,
                Utils.AES_128_BLOCK_SIZE_IN_BYTES);

        try {
            decrypt(modifiedCiphertext);
        } catch (RuntimeException e) {
            var message = e.getMessage();

            if (message.startsWith("ASCII non-compliant string: ")) {
                var ptStr = message.substring("ASCII non-compliant string: ".length());
                var ptBytes = Base64.getDecoder().decode(ptStr);

                //As the attacker, recovering the plaintext from the error, extract the key:
                //
                //P'_1 XOR P'_3
                var iv = Utils.xor(ptBytes, 0, ptBytes, Utils.AES_128_BLOCK_SIZE_IN_BYTES * 2, Utils.AES_128_BLOCK_SIZE_IN_BYTES);
                return iv;
            }
        }

        throw new RuntimeException("Decrypt didn't throw an exception with plaintext: ");
    }
}
