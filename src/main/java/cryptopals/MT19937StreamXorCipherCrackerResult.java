package cryptopals;

public record MT19937StreamXorCipherCrackerResult(
        int seed,
        byte[] decrypted,
        String decryptedString,
        double metric
) {
}
