package cryptopals.set1;

import cryptopals.SingleByteXorCipherCracker;
import cryptopals.ciphers.VigenereCipher;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
public class Challenge3SingleByteXorCipherCrackerTest {

    @Test
    void test() {
        var cipheredTextHex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

        var decrypted = new SingleByteXorCipherCracker().crackXorCipher(cipheredTextHex);

        log.info("{}", decrypted);

        assertEquals("Cooking MC's like a pound of bacon", decrypted.decryptedString());
    }

    @Test
    void test2() {
        var plaintext = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. \n" +
                "Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";

        var encrHex = VigenereCipher.encrypt(plaintext, "R");

        var decrypted = new SingleByteXorCipherCracker().crackXorCipher(encrHex);

        log.info("{}", decrypted);

        assertEquals(plaintext, decrypted.decryptedString());
    }

    @Test
    void test3() {
        var cipheredTextHex = "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f";

        var decrypted = new SingleByteXorCipherCracker().crackXorCipher(cipheredTextHex);

        log.info("{}", decrypted);

        assertEquals("Now that the party is jumping\n", decrypted.decryptedString());
    }
}
