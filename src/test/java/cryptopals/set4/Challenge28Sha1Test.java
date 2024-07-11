package cryptopals.set4;

import cryptopals.Utils;
import cryptopals.hash.SHA1;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
public class Challenge28Sha1Test {

    @Test
    void test() throws NoSuchAlgorithmException {
        var plaintext = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. \n" +
                "Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";

        var digest = new SHA1().digest(plaintext.getBytes(StandardCharsets.UTF_8));

        var md = MessageDigest.getInstance("SHA-1");

        assertEquals(
                HexFormat.of().formatHex(md.digest(plaintext.getBytes(StandardCharsets.UTF_8))),
                HexFormat.of().formatHex(digest)
        );
    }

    @Test
    void hashRandomBytes() throws NoSuchAlgorithmException {
        var input = Utils.randomBytes(1000);

        var hash = HexFormat.of().formatHex(new SHA1().digest(input));

        var md = MessageDigest.getInstance("SHA-1");

        assertEquals(HexFormat.of().formatHex(md.digest(input)), hash);
    }
}
