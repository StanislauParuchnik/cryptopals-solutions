package cryptopals;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HexFormat;

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

        return Base64.getDecoder().decode(fileString);
    }

    public static boolean areBlocksEqual(byte[] buffer, int block1Start, int block2Start, int blockSize) {
        return areBlocksEqual(buffer, block1Start, buffer, block2Start, blockSize);
    }

    public static boolean areBlocksEqual(byte[] buffer, int block1Start, byte[] buffer2, int block2Start, int blockSize) {
        for (int i = 0; i < blockSize; ++i) {
            if (buffer[block1Start + i] != buffer2[block2Start + i]) {
                return false;
            }
        }
        return true;
    }

    public static void validateBlockLength(byte[] buffer, String name) {
        if (buffer == null) {
            throw new IllegalArgumentException(name + " can't be null");
        }
        if (buffer.length != AES_128_BLOCK_SIZE_IN_BYTES) {
            throw new IllegalArgumentException(name + " length is incorrect");
        }
    }

    public static String toBlockHexString(byte[] buffer, int blockSize) {
        var sb = new StringBuilder("[");

        HexFormat.of().formatHex(sb, buffer, 0, Math.min(buffer.length, blockSize));

        for (int i = blockSize; i < buffer.length; i += blockSize) {
            sb.append(" ");
            HexFormat.of().formatHex(sb, buffer, i, Math.min(buffer.length, i + blockSize));
        }

        var rest = buffer.length % blockSize;
        if (rest > 0) {
            sb.append(" ");
            HexFormat.of().formatHex(sb, buffer, buffer.length - rest, buffer.length);

            var pad = blockSize - rest;
            sb.append("_".repeat(Math.max(0, pad)));
        }

        sb.append("]");

        return sb.toString();
    }
}
