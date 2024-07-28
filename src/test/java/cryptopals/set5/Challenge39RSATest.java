package cryptopals.set5;

import cryptopals.ciphers.RsaCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Challenge39RSATest {

    @Test
    void test() {
        var privateKey = RsaCipher.generatePrivateKey(1048);
        var publicKey = RsaCipher.generatePublicKey(privateKey);

        var message = "Hello World!";

        var rsa = new RsaCipher();

        var encrypted = rsa.apply(message.getBytes(StandardCharsets.UTF_8), publicKey);

        var decrypted = rsa.apply(encrypted, privateKey);

        assertEquals(message, new String(decrypted, StandardCharsets.UTF_8));
    }

    @Test
    void testAgainstBC() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var message = "Hello World!";
        var privateKey = RsaCipher.generatePrivateKey(1048);


        var encrypted = encryptWithBC(message.getBytes(StandardCharsets.UTF_8),
                privateKey.n(), privateKey.e());

        var rsa = new RsaCipher();
        var decrypted = rsa.apply(encrypted, privateKey);

        assertEquals(message, new String(decrypted, StandardCharsets.UTF_8));
    }

    private byte[] encryptWithBC(byte[] input, BigInteger n, BigInteger e) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        final Provider bc = new BouncyCastleProvider();

        KeyFactory rsaFactory = KeyFactory.getInstance("RSA", bc);
        var publicSpec = new RSAPublicKeySpec(n, e);
        RSAPublicKey testPublicKey = (RSAPublicKey) rsaFactory.generatePublic(publicSpec);

        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding", bc);
        c.init(Cipher.ENCRYPT_MODE, testPublicKey);
        return c.doFinal(input);
    }
}
