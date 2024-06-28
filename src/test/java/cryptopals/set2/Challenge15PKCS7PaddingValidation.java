package cryptopals.set2;

import cryptopals.PKCS7Padder;
import cryptopals.Utils;
import cryptopals.exceptions.InvalidPaddingException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class Challenge15PKCS7PaddingValidation {

    @Test
    void testValidPadding() {
        var str = "ICE ICE BABY\u0004\u0004\u0004\u0004";

        var result = new String(PKCS7Padder.unPadBuffer(
                str.getBytes(StandardCharsets.UTF_8), Utils.AES_128_BLOCK_SIZE_IN_BYTES));

        assertEquals("ICE ICE BABY", result);
    }

    @Test
    void testInvalidPadding1() {
        var str = "ICE ICE BABY\u0005\u0005\u0005\u0005";

        assertThrows(InvalidPaddingException.class, () -> {
            PKCS7Padder.unPadBuffer(
                    str.getBytes(StandardCharsets.UTF_8), Utils.AES_128_BLOCK_SIZE_IN_BYTES);
        });
    }

    @Test
    void testInvalidPadding2() {
        var str = "ICE ICE BABY\u0001\u0002\u0003\u0004";

        assertThrows(InvalidPaddingException.class, () -> {
            PKCS7Padder.unPadBuffer(
                    str.getBytes(StandardCharsets.UTF_8), Utils.AES_128_BLOCK_SIZE_IN_BYTES);
        });
    }
}
