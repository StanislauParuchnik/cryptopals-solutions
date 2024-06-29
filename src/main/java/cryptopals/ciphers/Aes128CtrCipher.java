package cryptopals.ciphers;

import cryptopals.Utils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class Aes128CtrCipher {

    private final Aes128EcbNoPaddingCipher aes128EcbNoPaddingCipher = new Aes128EcbNoPaddingCipher();

    public byte[] apply(byte[] input, byte[] key, long nonce) {
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("Input can't be null or empty");
        }
        Utils.validateBlockLength(key, "Key");

        var output = new byte[input.length];
        byte[] keyStream = new byte[Utils.AES_128_BLOCK_SIZE_IN_BYTES];

        var totalBLocks = (input.length - 1) / Utils.AES_128_BLOCK_SIZE_IN_BYTES + 1;
        var appliedIdx = 0;
        for (int block = 0; block < totalBLocks; ++block) {
            var keyStreamInput = ByteBuffer.allocate(Utils.AES_128_BLOCK_SIZE_IN_BYTES)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .putLong(nonce)
                    .putLong(block)
                    .array();

            aes128EcbNoPaddingCipher.encrypt(keyStreamInput, key,
                    0, Utils.AES_128_BLOCK_SIZE_IN_BYTES,
                    keyStream, 0);

            for (int i = 0; i < Utils.AES_128_BLOCK_SIZE_IN_BYTES && appliedIdx < input.length; ++i) {
                output[appliedIdx] = (byte) (input[appliedIdx] ^ keyStream[i]);
                appliedIdx++;
            }
        }

        return output;
    }
}
