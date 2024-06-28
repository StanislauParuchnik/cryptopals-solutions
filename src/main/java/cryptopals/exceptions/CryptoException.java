package cryptopals.exceptions;

public class CryptoException extends RuntimeException {
    public CryptoException(Throwable cause) {
        super(cause);
    }

    public CryptoException(String message) {
        super(message);
    }
}
