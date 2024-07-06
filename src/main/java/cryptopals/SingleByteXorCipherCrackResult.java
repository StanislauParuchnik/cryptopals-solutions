package cryptopals;


public record SingleByteXorCipherCrackResult(
        double metric,
        byte[] decrypted,
        String decryptedString,
        byte key
) {

    @Override
    public String toString() {
        return "Key: " + (char) key + " (" + key + ")" + "\n" +
                "Metric: " + metric + "\n" +
                "Text: " + decryptedString;
    }
}
