package cryptopals.set3;

import cryptopals.ciphers.Aes128CtrCipher;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
public class Challenge18Aes128CtrCipherTest {

    @Test
    void testExample() {
        var input = Base64.getDecoder().decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
        var key = "YELLOW SUBMARINE".getBytes(StandardCharsets.UTF_8);
        var nonce = 0;

        var decrypted = new String(new Aes128CtrCipher().apply(input, key, nonce));

        log.info(decrypted);
        assertEquals("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ", decrypted);
    }


    @Test
    void testKnownText() {
        var text = "This is my test text to check CTR Cipher";

        var key = "YELLOW SUBMARINE".getBytes(StandardCharsets.UTF_8);
        var nonce = 0;

        var cipher = new Aes128CtrCipher();
        var encrypted = cipher.apply(text.getBytes(StandardCharsets.UTF_8), key, nonce);
        var decrypted = new String(cipher.apply(encrypted, key, nonce));

        assertEquals(text, decrypted);
    }
}
