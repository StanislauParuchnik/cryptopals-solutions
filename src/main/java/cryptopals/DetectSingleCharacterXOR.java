package cryptopals;

import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;

import static java.util.Map.entry;

@Slf4j
public class DetectSingleCharacterXOR {

    private final SingleByteXorCipherCracker singleByteXorCipherCracker;

    public DetectSingleCharacterXOR() {
        this(new SingleByteXorCipherCracker());
    }

    public DetectSingleCharacterXOR(SingleByteXorCipherCracker singleByteXorCipherCracker) {
        this.singleByteXorCipherCracker = singleByteXorCipherCracker;
    }

    public Map.Entry<SingleByteXorCipherCrackResult, String> findSingleCharacterXor(List<String> hexInputs) {
        var minMetric = Double.MAX_VALUE;
        SingleByteXorCipherCrackResult bestCandidate = null;
        String bestCandidateInput = null;

        for (var inputHex : hexInputs) {
            var decryptedWithMetric = singleByteXorCipherCracker.crackXorCipher(inputHex);

            if (decryptedWithMetric.metric() < SingleByteXorCipherCracker.METRIC_LOG_LEVEL) {
                log.debug("{} - {}", decryptedWithMetric.decryptedString(), decryptedWithMetric.metric());
                log.debug("input text hex {}", inputHex);
            }

            if (decryptedWithMetric.metric() < minMetric) {
                minMetric = decryptedWithMetric.metric();
                bestCandidate = decryptedWithMetric;
                bestCandidateInput = inputHex;
            }
        }

        return entry(bestCandidate, bestCandidateInput);
    }
}
