package cryptopals;

import cryptopals.ciphers.MT19937StreamXorCipher;
import cryptopals.metrics.TextMetric;
import lombok.RequiredArgsConstructor;

import java.nio.charset.StandardCharsets;

@RequiredArgsConstructor
public class MT19937StreamXorCipherCracker {

    private final MT19937StreamXorCipher cipher;
    private final TextMetric textMetric;

    public MT19937StreamXorCipherCrackerResult crack(byte[] encrypted) {
        var decrypted = new byte[encrypted.length];

        var bestMetric = Double.MAX_VALUE;
        String bestDecrypted = null;
        int bestSeed = -1;

        var seedBound = 1 << 16;
        //just brute force it
        for (int seed = 0; seed < seedBound; ++seed) {
            cipher.apply(encrypted, seed, decrypted);

            var decryptedStr = new String(decrypted);
            var metric = textMetric.calculateMetric(decryptedStr);
            if (metric < bestMetric) {
                bestMetric = metric;
                bestDecrypted = decryptedStr;
                bestSeed = seed;
            }
        }

        return new MT19937StreamXorCipherCrackerResult(
                bestSeed,
                bestDecrypted != null ? bestDecrypted.getBytes(StandardCharsets.UTF_8) : null,
                bestDecrypted,
                bestMetric
        );
    }
}
