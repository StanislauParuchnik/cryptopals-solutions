package cryptopals;

import cryptopals.hash.SHA1;
import lombok.extern.slf4j.Slf4j;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Map;
import java.util.function.BiFunction;

import static java.util.Map.entry;

@Slf4j
public class SHA1PrefixKeyForger {

    public static final int MAX_KEY_LENGTH = 500;

    public static Map.Entry<byte[], byte[]> forgeHash(byte[] initialMessage, byte[] initialHash, byte[] appendMessage,
                                                      BiFunction<byte[], byte[], Boolean> hashVerifier) {
        var sha = new SHA1();
        var state = new int[5];
        for (int keyLength = 0; keyLength <= MAX_KEY_LENGTH; keyLength++) {
            log.debug("Checking key length {}", keyLength);

            var paddingBytes = generatePaddingBytes(keyLength + initialMessage.length);

            ByteBuffer.wrap(initialHash).order(ByteOrder.BIG_ENDIAN).asIntBuffer().get(state);
            var forgedHash = sha.digestWithInitialStateAndLength(appendMessage,
                    state,
                    keyLength + initialMessage.length + paddingBytes.length + appendMessage.length
            );

            var forgedMessage = buildForgedMessage(initialMessage, paddingBytes, appendMessage);
            if (hashVerifier.apply(forgedMessage, forgedHash)) {
                return entry(forgedMessage, forgedHash);
            }
        }

        return null;
    }

    private static byte[] generatePaddingBytes(int length) {
        var paddingBlockLength = ((((length + 8) >> 6) + 1) * 16) * 4 - length;
        var paddingBlock = new byte[paddingBlockLength];

        ByteBuffer.wrap(paddingBlock)
                .order(ByteOrder.BIG_ENDIAN)
                .put((byte) 0x80)
                .putInt(paddingBlockLength - 4, length * 8);


        return paddingBlock;
    }

    private static byte[] buildForgedMessage(byte[] initialMessage, byte[] paddingBytes, byte[] appendMessage) {
        return ByteBuffer.allocate(initialMessage.length + paddingBytes.length + appendMessage.length)
                .put(initialMessage)
                .put(paddingBytes)
                .put(appendMessage)
                .array();

    }

}
