package cryptopals.set3;

import cryptopals.CbcPaddingOracleAttack;
import cryptopals.Challenge17CbcPaddingOracle;
import cryptopals.Utils;
import cryptopals.ciphers.Aes128CbcPkcs7Cipher;
import cryptopals.ciphers.Aes128EcbNoPaddingCipher;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
public class Challenge17CbcPaddingOracleAttackTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
            "0123456789abcde",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef012345",
    })
    void test(String input) {

        var iv = new byte[Utils.AES_128_BLOCK_SIZE_IN_BYTES];
        new SecureRandom().nextBytes(iv);

        var paddingOracle = new Challenge17CbcPaddingOracle(
                new Aes128CbcPkcs7Cipher(new Aes128EcbNoPaddingCipher())
        );

        var encrypted = paddingOracle.encrypt(input.getBytes(StandardCharsets.UTF_8), iv);

        var cbcPaddingOracleAttack = new CbcPaddingOracleAttack(paddingOracle);
        var decrypted = new String(cbcPaddingOracleAttack.decrypt(encrypted, iv));

        log.info(decrypted);

        assertEquals(input, decrypted);
    }
}
