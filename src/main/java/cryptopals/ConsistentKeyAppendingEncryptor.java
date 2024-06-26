package cryptopals;

public interface ConsistentKeyAppendingEncryptor {

    byte[] encrypt(byte[] input);

    byte[] encrypt(byte[] input, int inputLen);
}
