package cryptopals;

import cryptopals.exceptions.InvalidPaddingException;

import java.util.Arrays;

public class PKCS7Padder {

    public static byte[] padBlock(byte[] input, int blockSize) {
        return padBlock(input, 0, blockSize);
    }

    public static byte[] padBlock(byte[] input, int inputOffset, int blockSize) {
        var result = new byte[blockSize];
        padBlock(input, inputOffset, result, 0, blockSize);

        return result;
    }

    public static void padBlock(byte[] input, int inputOffset, byte[] out, int outOffset, int blockSize) {
        if (input == null) {
            throw new IllegalArgumentException("Input block is null");
        }
        if (input.length == 0) {
            throw new IllegalArgumentException("Input block is empty");
        }
        if (input.length - inputOffset > blockSize) {
            throw new IllegalArgumentException("Input block length is greater than desired block size");
        }
        if (out == null || out.length - outOffset < blockSize) {
            throw new IllegalArgumentException("Output block is incorrect");
        }

        System.arraycopy(input, inputOffset, out, outOffset, input.length - inputOffset);
        Arrays.fill(out,
                input.length - inputOffset + outOffset,
                outOffset + blockSize,
                (byte) (blockSize - input.length + inputOffset));
    }

    public static void padEmptyBlock(byte[] out, int outOffset, int blockSize) {
        if (out == null || out.length - outOffset < blockSize) {
            throw new IllegalArgumentException("Output block is incorrect");
        }

        Arrays.fill(out, outOffset, outOffset + blockSize, (byte) blockSize);
    }

    public static byte[] unPadBuffer(byte[] input, int blockSize) {
        var numberOfAddedBytes = input[input.length - 1];

        if (numberOfAddedBytes > blockSize || numberOfAddedBytes <= 0) {
            throw new InvalidPaddingException("Padded number of bytes greater than blockSize=" + blockSize);
        }

        if (numberOfAddedBytes > input.length) {
            throw new InvalidPaddingException("Padded number of bytes greater than input length");
        }

        for (int i = 0; i < numberOfAddedBytes; ++i) {
            if (input[input.length - 1 - i] != numberOfAddedBytes) {
                throw new InvalidPaddingException("Invalid padding");
            }
        }

        var output = Arrays.copyOf(input,input.length - numberOfAddedBytes);

        return output;
    }
}
