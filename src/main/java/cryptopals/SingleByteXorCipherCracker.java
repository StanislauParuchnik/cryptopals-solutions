package cryptopals;

import cryptopals.metrics.FreqSquareDiffMetric;
import cryptopals.metrics.TextMetric;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.TreeMap;

@Slf4j
public class SingleByteXorCipherCracker {

    private final TextMetric textMetric;

    public static double METRIC_LOG_LEVEL = 0;

    public SingleByteXorCipherCracker() {
        this(new FreqSquareDiffMetric());
    }

    public SingleByteXorCipherCracker(TextMetric textMetric) {
        this.textMetric = textMetric;
    }

    public SingleByteXorCipherCrackResult crackXorCipher(String inputHex) {
        var inputBytes = HexFormat.of().parseHex(inputHex);

        return crackXorCipher(inputBytes);
    }

    public SingleByteXorCipherCrackResult crackXorCipher(byte[] inputBytes) {
        return crackXorCipher(inputBytes, 1, 0, 1).get(0);
    }

    public List<SingleByteXorCipherCrackResult> crackXorCipher(byte[] inputBytes,
                                                               int skipEachBytes,
                                                               int offset,
                                                               int maxNumberOfResultsReturned) {
        var decipheredLength = calculateDecipheredLength(inputBytes.length, skipEachBytes, offset);

        var resultMap = new TreeMap<Double, SingleByteXorCipherCrackResult>();

        for (int key = Byte.MIN_VALUE; key <= Byte.MAX_VALUE; key++) {
            var deciphered = new byte[decipheredLength];

            for (int i = 0; i < decipheredLength; i++) {
                var encrIdx = i * skipEachBytes + offset;
                deciphered[i] = (byte) (inputBytes[encrIdx] ^ key);
            }

            var text = new String(deciphered);

            var metric = textMetric.calculateMetric(text);

            if (metric < METRIC_LOG_LEVEL) {
                log.debug("{} - {} key {} ({})", text, metric, (char) key, key);
            }

            resultMap.put(metric, new SingleByteXorCipherCrackResult(metric, deciphered, text, (char) key));
            while (resultMap.size() > maxNumberOfResultsReturned) {
                resultMap.pollLastEntry();
            }
        }

        return new ArrayList<>(resultMap.values());
    }

    private static int calculateDecipheredLength(int inputLength, int skipEachBytes, int offset) {
        var decipheredLength = (inputLength - offset) / skipEachBytes;
        if (decipheredLength * skipEachBytes < (inputLength - offset)) {
            decipheredLength++;
        }

        return decipheredLength;
    }

}
