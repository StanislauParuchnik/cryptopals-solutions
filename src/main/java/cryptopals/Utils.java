package cryptopals;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

public class Utils {

    public static final int AES_128_BLOCK_SIZE_IN_BYTES = 128 / 8;


    private static final Logger log = LoggerFactory.getLogger(Utils.class);

    public static int hammingDistanceBits(byte[] a, byte[] b) {
        if (a.length != b.length) {
            throw new IllegalArgumentException("Byte arrays should have the same length");
        }

        return hammingDistanceBits(a, b, a.length);
    }

    public static int hammingDistanceBits(byte[] a, byte[] b, int size) {
        if (a.length < size || b.length < size) {
            throw new IllegalArgumentException("Invalid size");
        }

        int distance = 0;
        for (int i = 0; i < size; i++) {
            var diff = 0x00ff & (a[i] ^ b[i]);
            while (diff != 0) {
                distance += diff & 1;
                diff = diff >> 1;
            }
        }

        return distance;
    }

    public static byte[] readBase64FromFile(Path path) throws IOException {
        var fileString = Files.readString(path);
        fileString = fileString.replace("\n", "");
        log.debug(fileString);

        var result = Base64.getDecoder().decode(fileString);

        return result;
    }
}
