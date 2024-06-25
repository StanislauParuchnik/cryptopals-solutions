package cryptopals.set2;

import cryptopals.Challenge12ByteAtATimeEcbDecryption;
import cryptopals.Challenge12Encryptor;
import cryptopals.ciphers.Aes128EcbPkcs7Cipher;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
public class Challenge12ByteAtATimeEcbDecryptionTest {

    @Test
    void test() {
        var appendedBytes = Base64.getDecoder().decode(
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
                        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
                        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
                        "YnkK");

        var ecbDecryption = new Challenge12ByteAtATimeEcbDecryption(
                new Challenge12Encryptor(new Aes128EcbPkcs7Cipher(),
                        appendedBytes
                )
        );

        var decryptedAppendedString = new String(ecbDecryption.decryptAppendedText());

        log.info(decryptedAppendedString);

        assertEquals(new String(appendedBytes), decryptedAppendedString);
    }
}
