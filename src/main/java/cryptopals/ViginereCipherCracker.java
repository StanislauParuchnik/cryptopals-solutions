package cryptopals;

import cryptopals.metrics.TextMetric;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.util.Arrays;
import java.util.SortedMap;
import java.util.TreeMap;

@Slf4j
@Setter
@RequiredArgsConstructor
public class ViginereCipherCracker {

    private boolean printKeySizes = true;
    private int amountOfFirstKeyLengthToTry = 3;

    private final SingleByteXorCipherCracker singleByteXorCipherCracker;
    private final TextMetric textMetric;
    private final int numberOfSingleByteXorResults;

    public ViginereCipherCrackResult crackViginereCipher(byte[] input, int minKeyLength, int maxKeyLength) {
        var keyLengthProbabilities = determineKeyLengthProbability(input, minKeyLength, maxKeyLength);

        if (printKeySizes) {
            log.debug("Key length: {}", keyLengthProbabilities);
        }


//        log.debug("input length: {}", input.length);
        String bestCandidate = null;
        double bestCandidateMetric = Double.MAX_VALUE;
        byte[] bestKey = {};

        int i = 0;
        var iterator = keyLengthProbabilities.entrySet().iterator();
        while (i < amountOfFirstKeyLengthToTry && iterator.hasNext()) {
            byte[] decrypted = new byte[input.length];
            var keyLength = iterator.next().getValue();
            log.debug("Cracking for key length = {}", keyLength);

            byte[] key = new byte[keyLength];
            for (int keyByte = 0; keyByte < keyLength; keyByte++) {
                log.debug("Cracking key byte = {}", keyByte);
                var crackedForKeyResults = singleByteXorCipherCracker.crackXorCipher(
                        input,
                        keyLength,
                        keyByte,
                        numberOfSingleByteXorResults);

//                crackedForKeyResults.forEach(
//                        r ->  log.debug("{}\n", r)
//                );

                //copy cracked for key byte to result
//                log.debug("cracked length = {}", crackedForKeyByte.getKey().length());
                for (int j = 0; j < crackedForKeyResults.get(0).decrypted().length; ++j) {
//                    log.debug("j = {}, crackedIdx = {}", j, j * keyLength + keyByte);
                    decrypted[j * keyLength + keyByte] = crackedForKeyResults.get(0).decrypted()[j];
                }

                key[keyByte] = crackedForKeyResults.get(0).key();
            }

            var decryptedString = new String(decrypted);
            var metric = textMetric.calculateMetric(decryptedString);

            log.debug("{} - {}", decryptedString, metric);

            if (metric < bestCandidateMetric) {
                bestCandidate = decryptedString;
                bestCandidateMetric = metric;
                bestKey = key;
            }

            ++i;
        }

        return new ViginereCipherCrackResult(
                bestCandidateMetric,
                bestCandidate,
                bestKey
        );
    }

    private static SortedMap<Double, Integer> determineKeyLengthProbability(byte[] input, int minKeyLength, int maxKeyLength) {
        var result = new TreeMap<Double, Integer>();

        for (int keySize = minKeyLength; keySize <= maxKeyLength; keySize++) {
            //todo overflow handling if input is way too short
            var blocks = new byte[][]{
                    input,
                    Arrays.copyOfRange(input, keySize, keySize * 2),
                    Arrays.copyOfRange(input, keySize * 2, keySize * 3),
                    Arrays.copyOfRange(input, keySize * 3, keySize * 4)
            };

            var distance = 0;
            var totalComparisons = 0;
            for (int i = 0; i < blocks.length; ++i) {
                for (int j = i + 1; j < blocks.length; ++j) {
                    distance += Utils.hammingDistanceBits(
                            blocks[i],
                            blocks[j],
                            keySize
                    );
                    totalComparisons++;
                }
            }

            var distanceAverage = (double) distance / totalComparisons;
            var distanceNormalized = distanceAverage / keySize;
            result.put(distanceNormalized, keySize);
        }

        return result;
    }
}
