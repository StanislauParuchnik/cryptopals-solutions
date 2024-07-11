package cryptopals.set4;

import cryptopals.SHA1PrefixKeyForger;
import cryptopals.Utils;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.function.BiFunction;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@Slf4j
public class Challenge29BreakSHA1KeyedMACTest {

    @Test
    void test() throws NoSuchAlgorithmException {
        var key = Utils.randomBytes(Utils.SECURE_RANDOM.nextInt(2, 100));

        var message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".getBytes(StandardCharsets.UTF_8);
        var md = MessageDigest.getInstance("SHA-1");
        md.update(key);
        md.update(message);
        var hash = md.digest();

        var forged = SHA1PrefixKeyForger.forgeHash(message, hash, ";admin=true".getBytes(StandardCharsets.UTF_8),
                hashVerifier(key)
        );

        assertNotNull(forged);
        log.info("Forged message: {}", new String(forged.getKey()));
        log.info("Forged hash: {}", HexFormat.of().formatHex(forged.getValue()));
    }

    private BiFunction<byte[], byte[], Boolean> hashVerifier(byte[] key) {
        return (m, h) -> {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-1");
                md.update(key);
                md.update(m);
                return Arrays.equals(h, md.digest());
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        };
    }
}
