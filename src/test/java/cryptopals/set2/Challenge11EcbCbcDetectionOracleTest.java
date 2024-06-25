package cryptopals.set2;

import cryptopals.Challenge11EncryptEcbOrCbc;
import cryptopals.Utils;
import cryptopals.ciphers.Aes128CbcPkcs7Cipher;
import cryptopals.ciphers.Aes128EcbNoPaddingCipher;
import cryptopals.ciphers.Aes128EcbPkcs7Cipher;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Challenge11EcbCbcDetectionOracleTest {

    @Test
    void detectEcbOrCbc() {
        var input = new byte[Utils.AES_128_BLOCK_SIZE_IN_BYTES * 4];
        Arrays.fill(input, 0, input.length, (byte) 'A');

        var ecbOrCbcEncryptor = new Challenge11EncryptEcbOrCbc(
                new Aes128EcbPkcs7Cipher(),
                new Aes128CbcPkcs7Cipher(new Aes128EcbNoPaddingCipher())
        );

        for (int attempt = 0; attempt < 3000; ++attempt) {
            var encryptedWithMode = ecbOrCbcEncryptor.encryptEcbOrCbc(input);
            //if ecb blocks 2 and 3 are the same because ecb is stateless and deterministic
            if (Utils.areBlocksEqual(encryptedWithMode.getValue(),
                    Utils.AES_128_BLOCK_SIZE_IN_BYTES,
                    Utils.AES_128_BLOCK_SIZE_IN_BYTES * 2,
                    Utils.AES_128_BLOCK_SIZE_IN_BYTES)) {
                assertEquals("ECB", encryptedWithMode.getKey());
            } else {
                assertEquals("CBC", encryptedWithMode.getKey());
            }
        }
    }
}
