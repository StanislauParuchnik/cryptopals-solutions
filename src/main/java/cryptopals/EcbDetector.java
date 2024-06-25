package cryptopals;

import java.util.ArrayList;
import java.util.List;

public class EcbDetector {


    public static List<byte[]> detectEcb(List<byte[]> encryptedTexts, int blockSize) {
        //ECB is stateless and deterministic, find entry with the same blocks

        List<byte[]> result = new ArrayList<>();

        for (var encryptedText : encryptedTexts) {
            if (isEcb(encryptedText, blockSize)) {
                result.add(encryptedText);
            }
        }

        return result;
    }

    public static boolean isEcb(byte[] encryptedText, int blockSize) {
        for (int i = 0; i < encryptedText.length / blockSize; ++i) {
            for (int j = i + 1; j < encryptedText.length / blockSize; ++j) {
                if (Utils.areBlocksEqual(
                        encryptedText,
                        i * blockSize,
                        j * blockSize,
                        blockSize)) {

                    return true;
                }
            }
        }
        return false;
    }
}
