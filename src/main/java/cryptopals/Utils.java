package cryptopals;

import cryptopals.ciphers.Aes128EcbNoPaddingCipher;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

@Slf4j
public class Utils {

    public static final int AES_128_BLOCK_SIZE_IN_BYTES = 128 / 8;
    public static final SecureRandom SECURE_RANDOM = new SecureRandom();

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
            var diff = a[i] ^ b[i];
            while (diff != 0) {
                distance += diff & 1;
                diff = diff >>> 1;
            }
        }

        return distance;
    }

    public static byte[] readBase64FromFile(Path path) throws IOException {
        var fileString = Files.readString(path);
        fileString = fileString.replaceAll("[\r,\n]", "");
        log.debug(fileString);

        return Base64.getDecoder().decode(fileString);
    }

    public static byte[] readBase64FromFileAndDecryptECB(Path path, byte[] key) throws IOException {
        var inputBytes = Utils.readBase64FromFile(path);
        return new Aes128EcbNoPaddingCipher().decrypt(inputBytes, key);
    }

    public static List<byte[]> readBase64LinesFromFile(Path path) throws IOException {
        return Files.readString(path)
                .lines()
                .map(Base64.getDecoder()::decode)
                .toList();
    }

    public static boolean areBlocksEqual(byte[] buffer, int block1Start, int block2Start, int blockSize) {
        return areBlocksEqual(buffer, block1Start, buffer, block2Start, blockSize);
    }

    public static boolean areBlocksEqual(byte[] buffer, int block1Start, byte[] buffer2, int block2Start, int blockSize) {
        return Arrays.equals(buffer, block1Start, block1Start + blockSize,
                buffer2, block2Start, block2Start + blockSize);
    }

    public static void validateBlockLength(byte[] buffer, String name) {
        if (buffer == null) {
            throw new IllegalArgumentException(name + " can't be null");
        }
        if (buffer.length != AES_128_BLOCK_SIZE_IN_BYTES) {
            throw new IllegalArgumentException(name + " length is incorrect");
        }
    }

    public static void xor(byte[] input1, int input1Start, byte[] input2, int input2Start,
                           byte[] output, int outputStart, int length) {
        for (int i = 0; i < length; ++i) {
            output[outputStart + i] = (byte) (input1[input1Start + i] ^ input2[input2Start + i]);
        }
    }

    public static void xor(byte[] input1, int input1Start, byte value,
                           byte[] output, int outputStart, int length) {
        for (int i = 0; i < length; ++i) {
            output[outputStart + i] = (byte) (input1[input1Start + i] ^ value);
        }
    }

    public static void xor(byte[] buffer, int bufferStart, byte value, int length) {
        Utils.xor(buffer, bufferStart, value, buffer, bufferStart, length);
    }

    public static byte[] xor(byte[] input1, int input1Start, byte[] input2, int input2Start,
                             int length) {
        var output = new byte[length];
        xor(input1, input1Start, input2, input2Start, output, 0, length);
        return output;
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

    public static byte[] randomBytes(int length) {
        var bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }
}
