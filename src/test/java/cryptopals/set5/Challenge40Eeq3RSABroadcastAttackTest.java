package cryptopals.set5;

import cryptopals.RSAEeq3BroadcastAttack;
import cryptopals.Utils;
import cryptopals.ciphers.RsaCipher;
import cryptopals.ciphers.RsaPrivateKey;
import cryptopals.ciphers.RsaPublicKey;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class Challenge40Eeq3RSABroadcastAttackTest {
    private static final int keyLength = 1024;


    @Test
    void testBigMessage() {
        test(n -> {
            var nMin = n.stream().reduce(n.getFirst(), BigInteger::min);
            return nMin.subtract(BigInteger.ONE).toByteArray();
        });
    }

    @Test
    void testSmallMessage() {
        test(n -> BigInteger.TWO.toByteArray());
    }

    @Test
    void testRandomMessage() {
        test(n -> {
            var nMin = n.stream().reduce(n.getFirst(), BigInteger::min);
            return Utils.randomBigInteger(nMin).toByteArray();
        });
    }


    void test(Function<List<BigInteger>, byte[]> messageGenerator) {
        var privateKeys = generateCoprimeKeys();

        var publicKeys = privateKeys.stream()
                .map(RsaCipher::generatePublicKey)
                .toList();

        var messageBytes = messageGenerator.apply(publicKeys.stream().map(RsaPublicKey::n).toList());

        var rsa = new RsaCipher();

        var encryptedMessages = publicKeys.stream()
                .map(key -> rsa.apply(messageBytes, key))
                .toList();


        var crackedMessage = RSAEeq3BroadcastAttack.crackPlainText(encryptedMessages, publicKeys);

        assertNotNull(crackedMessage);
        assertEquals(HexFormat.of().formatHex(messageBytes), HexFormat.of().formatHex(crackedMessage));
    }

    private List<RsaPrivateKey> generateCoprimeKeys() {
        var takenPrimes = new HashSet<BigInteger>(6);
        var result = new ArrayList<RsaPrivateKey>();

        //just keys which modules are coprime. Otherwise, message is easily crackable by factorizing n
        //by calculating gcd of non-coprime modules
        for (int i = 0; i < 3; ++i) {
            while  (true) {
                var key = RsaCipher.generatePrivateKey(keyLength);
                if (takenPrimes.contains(key.p()) || takenPrimes.contains(key.q())) {
                    continue;
                }
                takenPrimes.add(key.p());
                takenPrimes.add(key.q());
                result.add(key);
                break;
            }
        }

        return result;
    }
}
