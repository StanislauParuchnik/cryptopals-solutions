package cryptopals;


public record SingleByteXorCipherCrackResult(
        double metric,
        byte[] decrypted,
        String decryptedString,
        char key
) {

    @Override
    public String toString() {
        return "Key: " + key + " (" + (byte) key + ")" + "\n" +
                "Metric: " + metric + "\n" +
                "Text: " + decryptedString;
    }
}
