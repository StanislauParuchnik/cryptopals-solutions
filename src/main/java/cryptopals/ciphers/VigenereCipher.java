package cryptopals.ciphers;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public class VigenereCipher {

    public static byte[] encrypt(byte[] input, byte[] key) {
        if (input.length == 0) {
            return new byte[0];
        }
        if (key.length == 0) {
            throw new IllegalArgumentException("Key cannot be empty");
        }
        byte[] cipher = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            cipher[i] = (byte) (input[i] ^ key[i % key.length]);
        }

        return cipher;
    }

    public static String encrypt(String input, String keyStr) {
        var key = keyStr.getBytes(StandardCharsets.UTF_8);

        var encrypted = encrypt(
                input.getBytes(StandardCharsets.UTF_8),
                key
        );

        return HexFormat.of().formatHex(encrypted);
    }

    public static String decrypt(String input, String keyStr) {
        var key = keyStr.getBytes(StandardCharsets.UTF_8);

        var decrypted = encrypt(
                input.getBytes(StandardCharsets.UTF_8),
                key
        );

        return new String(decrypted);
    }
}
