package cryptopals.set3;

import cryptopals.FixedNonceCtrCracker;
import cryptopals.SingleByteXorCipherCracker;
import cryptopals.Utils;
import cryptopals.ViginereCipherCracker;
import cryptopals.ciphers.Aes128CtrCipher;
import cryptopals.metrics.FreqSquareDiffMetric;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
public class Challenge19and20BreakFixedNonceCtrTest {

    @Test
    void test() throws IOException {
        var plainTexts = Utils.readBase64LinesFromFile(Paths.get("src\\test\\resources\\set3\\set3Challenge20.txt"));
        var encrypted = encryptPlainTexts(plainTexts);
        var fixedNonceCtrCracker = new FixedNonceCtrCracker(createViginereCracker());

        var crackResult = fixedNonceCtrCracker.breakFixedNonceCtr(encrypted);


        crackResult.decrypted().forEach(pt -> System.out.println(new String(pt)));
        assertEquals("i'm rated \"R\"...this is a warning, ya better void / P",
                new String(crackResult.decrypted().get(0)));
    }

    private List<byte[]> encryptPlainTexts(List<byte[]> plainTexts) {
        var nonce = 0;

        var key = Utils.randomBytes(Utils.AES_128_BLOCK_SIZE_IN_BYTES);

        var ctrCipher = new Aes128CtrCipher();

        return plainTexts.stream()
                .map(pt -> ctrCipher.apply(pt, key, nonce))
                .toList();
    }

    private ViginereCipherCracker createViginereCracker() {
        //don't check bigrams for single xor crack because text decrypted for key
        //element is not normal english text
        var xorMetric = new FreqSquareDiffMetric(1, 0);
        var singleXorCracker = new SingleByteXorCipherCracker(xorMetric);

        var metric = new FreqSquareDiffMetric();
        var viginereCracker = new ViginereCipherCracker(singleXorCracker, metric, 1);

        return viginereCracker;
    }
}
