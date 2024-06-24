package cryptopals.set1;

import cryptopals.DetectSingleCharacterXOR;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
public class Challenge4DetectSingleCharacterXORTest {

    @Test
    void test() throws IOException {
        var input = Files.readAllLines(Paths.get("src\\test\\resources\\set1\\set1Challenge4.txt"));

        var result = new DetectSingleCharacterXOR().findSingleCharacterXor(input);

        log.info("key: {} ({})", result.getKey().key(), (byte) result.getKey().key());

        assertEquals("Now that the party is jumping\n", result.getKey().decryptedString());
        assertEquals("7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f", result.getValue());
    }
}
