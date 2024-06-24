package cryptopals.set1;

import cryptopals.ciphers.VigenereCipher;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
public class Challenge5ViginereCipherTest {

    @Test
    void test() {
        var input = "Burning 'em, if you ain't quick and nimble\n" +
                "I go crazy when I hear a cymbal";

        var result = VigenereCipher.encrypt(input, "ICE");

        assertEquals("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a262263242727" +
                "65272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", result);
    }

}

