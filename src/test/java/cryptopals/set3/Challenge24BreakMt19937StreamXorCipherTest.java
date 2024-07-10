package cryptopals.set3;

import cryptopals.MT19937StreamXorCipherCracker;
import cryptopals.ciphers.MT19937StreamXorCipher;
import cryptopals.metrics.FreqSquareDiffMetric;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
public class Challenge24BreakMt19937StreamXorCipherTest {

    @Test
    void testEncryptionAndDecryption() {
        var plaintext = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. \n" +
                "Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";


        var cipher = new MT19937StreamXorCipher();

        var seed = new SecureRandom().nextInt(0, 1<<16); //16 bit
        var encrypted = cipher.apply(plaintext.getBytes(StandardCharsets.UTF_8), seed);

        var decrypted = cipher.apply(encrypted, seed);

        assertEquals(plaintext, new String(decrypted));
    }

    @Test
    void testCrack() {
        var plaintext = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. \n" +
                "Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";


        var cipher = new MT19937StreamXorCipher();

        var seed = new SecureRandom().nextInt(0, 1<<16); //16 bit
        var encrypted = cipher.apply(plaintext.getBytes(StandardCharsets.UTF_8), seed);

        var cracker = new MT19937StreamXorCipherCracker(cipher, new FreqSquareDiffMetric());

        var crackResult = cracker.crack(encrypted);
        log.info(crackResult.toString());


        assertEquals(plaintext, crackResult.decryptedString());
        assertEquals(seed, crackResult.seed());
    }
}
