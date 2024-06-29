package cryptopals;

public interface PaddingOracle {

    boolean isPaddingCorrect(byte[] iv, byte[] encrypted, int length);
}
