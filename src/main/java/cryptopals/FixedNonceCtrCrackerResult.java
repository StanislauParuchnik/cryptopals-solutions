package cryptopals;

import java.util.List;

public record FixedNonceCtrCrackerResult(
        List<byte[]> decrypted,
        byte[] key
) {
}
