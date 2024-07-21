package cryptopals;

import cryptopals.hash.MD4;
import lombok.extern.slf4j.Slf4j;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Map;
import java.util.function.BiFunction;

import static java.util.Map.entry;

@Slf4j
public class MD4PrefixKeyForger {

    public static final int MAX_KEY_LENGTH = 500;

    public static Map.Entry<byte[], byte[]> forgeHash(byte[] initialMessage, byte[] initialHash, byte[] appendMessage,
                                                      BiFunction<byte[], byte[], Boolean> hashVerifier) {
        var md4 = new MD4();
        var state = new int[4];
        for (int keyLength = 0; keyLength <= MAX_KEY_LENGTH; keyLength++) {
            log.debug("Checking key length {}", keyLength);

            var paddingBytes = MD4.generateTail(keyLength + initialMessage.length);

            ByteBuffer.wrap(initialHash).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(state);
            var forgedHash = md4.digestWithInitialStateAndLength(appendMessage,
                    state,
                    keyLength + initialMessage.length + paddingBytes.length
            );

            var forgedMessage = buildForgedMessage(initialMessage, paddingBytes, appendMessage);
            if (hashVerifier.apply(forgedMessage, forgedHash)) {
                return entry(forgedMessage, forgedHash);
            }
        }

        return null;
    }

    private static byte[] buildForgedMessage(byte[] initialMessage, byte[] paddingBytes, byte[] appendMessage) {
        return Utils.concat(initialMessage, paddingBytes, appendMessage);
    }

}
