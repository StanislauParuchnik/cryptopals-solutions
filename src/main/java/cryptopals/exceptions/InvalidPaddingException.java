package cryptopals.exceptions;

public class InvalidPaddingException extends CryptoException {

    public InvalidPaddingException(Throwable cause) {
        super(cause);
    }

    public InvalidPaddingException(String message) {
        super(message);
    }
}
