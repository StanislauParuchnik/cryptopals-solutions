package cryptopals.set2;

import cryptopals.PKCS7Padder;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Challenge9PKCS7PaddingTest {

    @Test
    void testPKCS7Padding() {

        var inputTxt = "YELLOW SUBMARINE";

        var resultBytes = PKCS7Padder.padBlock(inputTxt.getBytes(StandardCharsets.UTF_8), 20);

        assertEquals("YELLOW SUBMARINE\u0004\u0004\u0004\u0004", new String(resultBytes));

    }
}
