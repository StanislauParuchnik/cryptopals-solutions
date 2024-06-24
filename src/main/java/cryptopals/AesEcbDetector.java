package cryptopals;

import java.util.ArrayList;
import java.util.List;

import static cryptopals.Utils.AES_128_BLOCK_SIZE_IN_BYTES;

public class AesEcbDetector {


    public static List<byte[]> detectAesEcb(List<byte[]> encryptedTexts) {
        //ECB is stateless and deterministic, find entry with the same blocks

        List<byte[]> result = new ArrayList<>();

        for (var encryptedText : encryptedTexts) {
            boolean shouldBreak = false;
            for (int i = 0; i < encryptedText.length / AES_128_BLOCK_SIZE_IN_BYTES; ++i) {
                for (int j = i + 1; j < encryptedText.length / AES_128_BLOCK_SIZE_IN_BYTES; ++j) {
                    if (areBlocksEqual(
                            encryptedText,
                            i * AES_128_BLOCK_SIZE_IN_BYTES,
                            j * AES_128_BLOCK_SIZE_IN_BYTES,
                            AES_128_BLOCK_SIZE_IN_BYTES)) {
                        result.add(encryptedText);
                        shouldBreak = true;
                        break;
                    }
                }
                if (shouldBreak) {
                    break;
                }
            }
        }

        return result;
    }

    private static boolean areBlocksEqual(byte[] buffer, int block1Start, int block2Start, int blockSize) {
        for (int i = 0; i < blockSize; ++i) {
            if (buffer[block1Start + i] != buffer[block2Start + i]) {
                return false;
            }
        }
        return true;
    }
}
