package cryptopals;

public interface ConsistentKeyEncryptor {

    byte[] encrypt(byte[] input);

    byte[] encrypt(byte[] input, int inputLen);
}
