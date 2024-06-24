package cryptopals.set1;

import cryptopals.AesEcbDetector;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
public class Challenge8DetectAesECBTest {

    @Test
    void testDecrypt() throws IOException {
        var fileString = Files.readString(Paths.get("src\\test\\resources\\set1\\set1Challenge8.txt"));

        var encryptedTexts = Arrays.stream(fileString.split("\n"))
                .map(HexFormat.of()::parseHex)
                .toList();

        var result = AesEcbDetector.detectAesEcb(encryptedTexts);

        System.out.println(result);

        assertEquals(1, result.size());
    }

}
