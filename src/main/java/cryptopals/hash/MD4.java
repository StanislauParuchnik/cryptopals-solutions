//implementation based on https://rosettacode.org/wiki/MD4#Without_external_libraries

package cryptopals.hash;

import java.util.Arrays;
import java.util.List;

public class MD4 {

    private static final int BLOCK_LENGTH = 64;

    private long count;
    private int[] context = new int[4];
    private int[] extra = new int[16];
    private byte[] buffer = new byte[BLOCK_LENGTH];

    public MD4() {
        engineReset();
//        System.out.println("initial context: " + Utils.toHex(context));
    }

    private static int rotate(int t, int s) {
        return t << s | t >>> (32 - s);
    }

    private static int ff(int a, int b, int c, int d, int x, int s) {
        return rotate(a + ((b & c) | (~b & d)) + x, s);
    }

    private static int gg(int a, int b, int c, int d, int x, int s) {
        return rotate(a + ((b & (c | d)) | (c & d)) + x + 0x5A827999, s);
    }

    private static int hh(int a, int b, int c, int d, int x, int s) {
        return rotate(a + (b ^ c ^ d) + x + 0x6ED9EBA1, s);
    }

    public byte[] digestWithInitialStateAndLength(byte[] appendMessage, int[] state, int i) {
        count = i;
        context[0] = state[0];
        context[1] = state[1];
        context[2] = state[2];
        context[3] = state[3];
        Arrays.fill(extra, 0);
        Arrays.fill(buffer, (byte) 0);

//        System.out.println("forged context: " + Utils.toHex(context));
        return engineDigest(appendMessage);
    }

    public byte[] engineDigest(byte[] input) {
        engineUpdate(input, 0, input.length);

        byte[] tail = generateTail(count);

//        System.out.println("tail: " + HexFormat.of().formatHex(tail));

        engineUpdate(tail, 0, tail.length);

        byte[] result = new byte[16];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                result[i * 4 + j] = (byte) (context[i] >>> (8 * j));
            }
        }

//        System.out.println("Context after tail: " + Utils.toHex(context));
//        System.out.println("Digest: " + HexFormat.of().formatHex(result));

        engineReset();
        return result;
    }

    private void engineUpdate(byte[] aMessageBytes, int aOffset, int aMessageLength) {
        if (aOffset < 0 || aMessageLength < 0 || (long) aOffset + aMessageLength > (long) aMessageBytes.length) {
            throw new ArrayIndexOutOfBoundsException("Incorrect arguments for method engineUpdate");
        }

        int bufferIndex = (int) (count % BLOCK_LENGTH);
        count += aMessageLength;
        final int partialLength = BLOCK_LENGTH - bufferIndex;
        int i = 0;

        if (aMessageLength >= partialLength) {
            System.arraycopy(aMessageBytes, aOffset, buffer, bufferIndex, partialLength);
            transform(buffer, 0);
            i = partialLength;
            while (i + BLOCK_LENGTH - 1 < aMessageLength) {
                transform(aMessageBytes, aOffset + i);
                i += BLOCK_LENGTH;
            }
            bufferIndex = 0;
        }

        if (i < aMessageLength) {
            System.arraycopy(aMessageBytes, aOffset + i, buffer, bufferIndex, aMessageLength - i);
        }
    }

    public static byte[] generateTail(long length) {
        final int bufferIndex = (int) (length % BLOCK_LENGTH);
        final int paddingLength = (bufferIndex < 56) ? 56 - bufferIndex : 120 - bufferIndex;
        byte[] tail = new byte[paddingLength + 8];
        tail[0] = (byte) 0x80;

        for (int i = 0; i < 8; i++) {
            tail[paddingLength + i] = (byte) ((length * 8) >>> (8 * i));
        }
        return tail;
    }

    private void transform(byte[] aBuffer, int aOffset) {
//        System.out.println("transform, offset = " + aOffset);
//        System.out.println("context: " + Utils.toHex(context));
//        System.out.println("data: " + Utils.singleBlockHexString(aBuffer, aOffset, 64));
        for (int i = 0; i < 16; i++) {
            extra[i] = ((aBuffer[aOffset++] & 0xff)) |
                    ((aBuffer[aOffset++] & 0xff) << 8) |
                    ((aBuffer[aOffset++] & 0xff) << 16) |
                    ((aBuffer[aOffset++] & 0xff) << 24);
        }

        int a = context[0];
        int b = context[1];
        int c = context[2];
        int d = context[3];

        for (int i : List.of(0, 4, 8, 12)) {
            a = ff(a, b, c, d, extra[i + 0], 3);
            d = ff(d, a, b, c, extra[i + 1], 7);
            c = ff(c, d, a, b, extra[i + 2], 11);
            b = ff(b, c, d, a, extra[i + 3], 19);
        }

        for (int i : List.of(0, 1, 2, 3)) {
            a = gg(a, b, c, d, extra[i + 0], 3);
            d = gg(d, a, b, c, extra[i + 4], 5);
            c = gg(c, d, a, b, extra[i + 8], 9);
            b = gg(b, c, d, a, extra[i + 12], 13);
        }

        for (int i : List.of(0, 2, 1, 3)) {
            a = hh(a, b, c, d, extra[i + 0], 3);
            d = hh(d, a, b, c, extra[i + 8], 9);
            c = hh(c, d, a, b, extra[i + 4], 11);
            b = hh(b, c, d, a, extra[i + 12], 15);
        }

        context[0] += a;
        context[1] += b;
        context[2] += c;
        context[3] += d;
    }

    private void engineReset() {
        count = 0;
        context[0] = 0x67452301;
        context[1] = 0xefcdab89;
        context[2] = 0x98badcfe;
        context[3] = 0x10325476;
        Arrays.fill(extra, 0);
        Arrays.fill(buffer, (byte) 0);
    }
}