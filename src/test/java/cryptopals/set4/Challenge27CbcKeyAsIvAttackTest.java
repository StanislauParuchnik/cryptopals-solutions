package cryptopals.set4;

import cryptopals.CbcKeyAsIvAttack;
import cryptopals.Utils;
import cryptopals.ciphers.Aes128CbcPkcs7Cipher;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
public class Challenge27CbcKeyAsIvAttackTest {

    @Test
    void test() {
        byte[] key = Utils.randomBytes(Utils.AES_128_BLOCK_SIZE_IN_BYTES);

        CbcKeyAsIvAttack instance = new CbcKeyAsIvAttack(new Aes128CbcPkcs7Cipher(), key);

        var str = "asdfghjk".repeat(3 * (Utils.AES_128_BLOCK_SIZE_IN_BYTES / 2));
        var ciphertext = instance.encrypt(str);

        var extractedKey = instance.extractIV(ciphertext);
        log.info(Utils.toBlockHexString(extractedKey, Utils.AES_128_BLOCK_SIZE_IN_BYTES));

        assertEquals(Utils.toBlockHexString(key, key.length),
                Utils.toBlockHexString(extractedKey, extractedKey.length));
    }
}
