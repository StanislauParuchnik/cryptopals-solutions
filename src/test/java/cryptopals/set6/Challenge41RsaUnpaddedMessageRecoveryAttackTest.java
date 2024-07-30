package cryptopals.set6;

import cryptopals.OneTimeRsaDecryptor;
import cryptopals.RsaUnpaddedMessageRecoveryAttack;
import cryptopals.ciphers.RsaCipher;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class Challenge41RsaUnpaddedMessageRecoveryAttackTest {

    @Test
    void testCantDecryptSameMessageTwice() throws NoSuchAlgorithmException {
        var message = """
                {
                  time: 1356304276,
                  social: '555-55-5555',
                }""";

        var rsaCipher = new RsaCipher();
        var privateKey = RsaCipher.generatePrivateKey(1024);
        var publicKey = RsaCipher.generatePublicKey(privateKey);
        var encrypted = rsaCipher.apply(message.getBytes(StandardCharsets.UTF_8), publicKey);

        var oneTimeRsaDecryptor = new OneTimeRsaDecryptor(rsaCipher, privateKey);


        var decrypted1 = oneTimeRsaDecryptor.decrypt(encrypted);
        assertEquals(message, new String(decrypted1));


        var thrown = assertThrows(IllegalArgumentException.class, () -> oneTimeRsaDecryptor.decrypt(encrypted));
        assertEquals("Input was already decrypted", thrown.getMessage());
    }


    @Test
    void testAttack() throws NoSuchAlgorithmException {
        var message = """
                {
                  time: 1356304276,
                  social: '555-55-5555',
                }""";

        var rsaCipher = new RsaCipher();
        var privateKey = RsaCipher.generatePrivateKey(1024);
        var publicKey = RsaCipher.generatePublicKey(privateKey);
        var encrypted = rsaCipher.apply(message.getBytes(StandardCharsets.UTF_8), publicKey);

        var oneTimeRsaDecryptor = new OneTimeRsaDecryptor(rsaCipher, privateKey);
        var attack = new RsaUnpaddedMessageRecoveryAttack(oneTimeRsaDecryptor);


        var decrypted1 = oneTimeRsaDecryptor.decrypt(encrypted);
        assertEquals(message, new String(decrypted1));


        var decrypted2 = attack.bypassOneTimeDecryption(encrypted, publicKey);
        assertEquals(message, new String(decrypted2));
    }
}
