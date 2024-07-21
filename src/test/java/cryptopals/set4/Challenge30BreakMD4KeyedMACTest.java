package cryptopals.set4;

import cryptopals.MD4PrefixKeyForger;
import cryptopals.Utils;
import cryptopals.hash.MD4;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.function.BiFunction;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Slf4j
public class Challenge30BreakMD4KeyedMACTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void testBCMD4() throws NoSuchAlgorithmException {
        var bytes = "Erat autem homo ex pharisaesis, Nicodemus nominae, princ".getBytes(StandardCharsets.UTF_8);

        var bcMD = MessageDigest.getInstance("MD4");
        var digest = bcMD.digest(bytes);

        System.out.println(HexFormat.of().formatHex(digest));
        assertEquals("6714ed6045260b80ddb0e7efda374639", HexFormat.of().formatHex(digest));
    }

    @Test
    void testRosettaMD4() throws NoSuchAlgorithmException {
        var bytes = "Erat autem homo ex pharisaesis, Nicodemus nominae, princ".getBytes(StandardCharsets.UTF_8);

        MD4 md4 = new MD4();
        byte[] digest = md4.engineDigest(bytes);

        System.out.println(HexFormat.of().formatHex(digest));
        assertEquals("6714ed6045260b80ddb0e7efda374639", HexFormat.of().formatHex(digest));
    }

    @Test
    void testForge() throws NoSuchAlgorithmException {
        var key = Utils.randomBytes(Utils.SECURE_RANDOM.nextInt(2, 100));

        var message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".getBytes(StandardCharsets.UTF_8);
        var md = MessageDigest.getInstance("MD4");
        md.update(key);
        md.update(message);
        var hash = md.digest();

        var forged = MD4PrefixKeyForger.forgeHash(message, hash, ";admin=true".getBytes(StandardCharsets.UTF_8),
                hashVerifier(key)
        );


        assertNotNull(forged);
        log.info("Forged message: {}", new String(forged.getKey()));
        log.info("Forged hash: {}", HexFormat.of().formatHex(forged.getValue()));
    }

    private BiFunction<byte[], byte[], Boolean> hashVerifier(byte[] key) {
        return (m, h) -> {
            try {
                MessageDigest md = MessageDigest.getInstance("MD4");
                md.update(key);
                md.update(m);
                return Arrays.equals(h, md.digest());
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        };
    }
}
