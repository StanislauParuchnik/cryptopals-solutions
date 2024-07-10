package cryptopals.ciphers;

import cryptopals.random.MT19937Rng;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class MT19937StreamXorCipher {

    public byte[] apply(byte[] input, int seed) {
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("Input is empty");
        }
        var result = new byte[input.length];
        apply(input, seed, result);
        return result;
    }

    public void apply(byte[] input, int seed,
                      byte[] output) {
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("Input is empty");
        }
        if (output == null) {
            throw new IllegalArgumentException("Output is null");
        }
        if (output.length != input.length) {
            throw new IllegalArgumentException("Output length does not match input length");
        }

        var rng = new MT19937Rng(seed);
        var keyStream = new byte[4];
        generateKeyStream(keyStream, rng.nextInt());
        for (int i = 0, j = 0; i < input.length; ++i, ++j) {
            if (j == 4) {
                generateKeyStream(keyStream, rng.nextInt());
                j = 0;
            }
            output[i] = (byte) (input[i] ^ keyStream[j]);
        }
    }

    private void generateKeyStream(byte[] keyStream, int keyInt) {
        ByteBuffer.wrap(keyStream).putInt(keyInt).order(ByteOrder.BIG_ENDIAN);
    }
}
