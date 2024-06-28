package cryptopals.set2;

import cryptopals.CbcBitflippingAttack;
import cryptopals.ciphers.Aes128CbcPkcs7Cipher;
import cryptopals.ciphers.Aes128EcbNoPaddingCipher;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class Challenge16CbcBitflippingAttackTest {

    @Test
    void test() {
        var instance = new CbcBitflippingAttack(new Aes128CbcPkcs7Cipher(new Aes128EcbNoPaddingCipher()));


        var forged = instance.forgeAdmin();

        assertTrue(instance.isAdmin(forged));
    }
}
