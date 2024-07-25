package cryptopals.set3;

import cryptopals.CbcPaddingOracleAttack;
import cryptopals.Challenge17CbcPaddingOracle;
import cryptopals.Utils;
import cryptopals.ciphers.Aes128CbcPkcs7Cipher;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

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

        var iv = Utils.randomBytes(Utils.AES_128_BLOCK_SIZE_IN_BYTES);

        var paddingOracle = new Challenge17CbcPaddingOracle(new Aes128CbcPkcs7Cipher());

        var encrypted = paddingOracle.encrypt(input.getBytes(StandardCharsets.UTF_8), iv);

        var cbcPaddingOracleAttack = new CbcPaddingOracleAttack(paddingOracle);
        var decrypted = new String(cbcPaddingOracleAttack.decrypt(encrypted, iv));

        log.info(decrypted);

        assertEquals(input, decrypted);
    }

    @ParameterizedTest
    @CsvSource({
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93,6eabd557bbbbfcdb85aaf1971619336e,64821555b1fe8498465a6d0c6e0ba67f",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=,c5ef25e8e64901d506dbbccc1b18843d,5fd69b4c40b05bcbbfdd13db052783a7",
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=,213e8d0b89184fb5ea806987cf67b5c0,e117acfd96658f323ec700cb0910505f",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==,7acd56ac4a38a39163a02ef3294e3eac,5e61c9099eac8da739b824798bb3bfab",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==,e126b2cbdbbd08b3ccf9ad471468eb56,f9a7e7e02e559c622ecf0e4e0f451c93",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==,be5d3a96e884aac4b0429114d8ccd43f,acedbb1be155131da949664a34e356c4",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==,cdebbb03ddf314be3e3cb7ea224431ec,c296aab63ca604d17d21c7331e6d9734"
    })
    void testCbcEdgeCase(String input, String ivHex, String keyHex) {

        var iv = HexFormat.of().parseHex(ivHex);

        var paddingOracle = new Challenge17CbcPaddingOracle(new Aes128CbcPkcs7Cipher(),
                HexFormat.of().parseHex(keyHex));

        var encrypted = paddingOracle.encrypt(input.getBytes(StandardCharsets.UTF_8), iv);

        var cbcPaddingOracleAttack = new CbcPaddingOracleAttack(paddingOracle);
        var decrypted = new String(cbcPaddingOracleAttack.decrypt(encrypted, iv));

        log.info(decrypted);

        assertEquals(input, decrypted);
    }
}
