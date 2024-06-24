package cryptopals;

import java.util.Base64;
import java.util.HexFormat;

public class HexToBase64 {

    public static String hexToBase64(String hex) {
        var bytes = HexFormat.of().parseHex(hex);
        return Base64.getEncoder().encodeToString(bytes);
    }

}
