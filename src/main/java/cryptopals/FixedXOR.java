package cryptopals;

import java.util.HexFormat;

public class FixedXOR {

    public static byte[] fixedXor(byte[] buf1, byte[] buf2) {
        if (buf1.length != buf2.length) {
            throw new RuntimeException("buffer length does not match");
        }
        var result = new byte[buf1.length];
        for (int i = 0; i < buf1.length; i++) {
            result[i] = (byte) (buf1[i] ^ buf2[i]);
        }
        return result;
    }

    public static String fixedXorHex(String hex1, String hex2) {
        var buf1 = HexFormat.of().parseHex(hex1);
        var buf2 = HexFormat.of().parseHex(hex2);

        var resBytes = fixedXor(buf1, buf2);

        return HexFormat.of().formatHex(resBytes);
    }
}
