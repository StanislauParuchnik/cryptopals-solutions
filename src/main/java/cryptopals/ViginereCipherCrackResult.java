package cryptopals;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

@RequiredArgsConstructor
@ToString
@Data
public class ViginereCipherCrackResult {
    private final double metric;
    private final String decryptedString;
    private final byte[] key;
}
