package cryptopals;

public interface ConsistentKeyEncryptionOracle {

    byte[] encrypt(byte[] input);

    byte[] encrypt(byte[] input, int inputLen);
}
