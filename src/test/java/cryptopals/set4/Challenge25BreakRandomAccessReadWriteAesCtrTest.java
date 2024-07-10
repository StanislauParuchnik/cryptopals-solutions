package cryptopals.set4;

import cryptopals.Aes128RandomReadWriteEditor;
import cryptopals.RandomAccessReadWriteAesCtrCracker;
import cryptopals.Utils;
import cryptopals.ciphers.Aes128CtrCipher;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Challenge25BreakRandomAccessReadWriteAesCtrTest {


    private static final Logger log = LoggerFactory.getLogger(Challenge25BreakRandomAccessReadWriteAesCtrTest.class);

    @Test
    void test() throws IOException {
        var plainTextBytes = Utils.readBase64FromFileAndDecryptECB(
                Paths.get("src\\test\\resources\\set1\\set1Challenge7.txt"),
                "YELLOW SUBMARINE".getBytes(StandardCharsets.UTF_8)
        );

        byte[] key = Utils.randomBytes(Utils.AES_128_BLOCK_SIZE_IN_BYTES);
        var nonce = Utils.SECURE_RANDOM.nextLong();

        var ctrEncrypted = new Aes128CtrCipher().apply(plainTextBytes, key, nonce);

        var editor = new Aes128RandomReadWriteEditor(key, nonce);
        var cracker = new RandomAccessReadWriteAesCtrCracker(editor);


        var crackedPlainText = new String(cracker.crack(ctrEncrypted));
        log.info(crackedPlainText);


        assertEquals(new String(plainTextBytes), crackedPlainText);
    }
}
