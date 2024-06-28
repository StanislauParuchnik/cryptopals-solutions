package cryptopals.set2;

import cryptopals.ByteAtATimeEcbAppendedDataDecryption;
import cryptopals.PrependingAndAppendingConsistentKeyEncryptionOracle;
import cryptopals.Utils;
import cryptopals.ciphers.Aes128EcbPkcs7Cipher;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
public class Challenge14ByteAtATimeEcbDecryptionTest {


    @Test
    void testPrefixSizeLessThanBlockSize() {
        test(5);
    }

    @Test
    void testPrefixSizeLessThanBlockSize2() {
        test(Utils.AES_128_BLOCK_SIZE_IN_BYTES - 5);
    }

    @Test
    void testPrefixSizeEqualsBlockSize() {
        test(Utils.AES_128_BLOCK_SIZE_IN_BYTES);
    }

    @Test
    void testPrefixSizeGreaterThanBlockSize() {
        test(Utils.AES_128_BLOCK_SIZE_IN_BYTES + 5);
    }



    private void test(int prependedBytesNumber) {
        var appendedBytes = Base64.getDecoder().decode(
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
                        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
                        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
                        "YnkK");

        var ecbDecryption = new ByteAtATimeEcbAppendedDataDecryption(
                new PrependingAndAppendingConsistentKeyEncryptionOracle(new Aes128EcbPkcs7Cipher(),
                        appendedBytes,
                        prependedBytesNumber
                )
        );

        var decryptedAppendedString = new String(ecbDecryption.decryptAppendedText());

        log.info(decryptedAppendedString);

        assertEquals(new String(appendedBytes), decryptedAppendedString);
    }
}
