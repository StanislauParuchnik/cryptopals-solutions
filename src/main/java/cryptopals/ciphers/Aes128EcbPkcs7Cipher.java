package cryptopals.ciphers;

public class Aes128EcbPkcs7Cipher extends Aes128EcbCipher{

    public Aes128EcbPkcs7Cipher() {
        super("PKCS5Padding");
    }
}
