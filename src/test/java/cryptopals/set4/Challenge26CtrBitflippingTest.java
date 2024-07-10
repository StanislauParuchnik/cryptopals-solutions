package cryptopals.set4;

import cryptopals.CtrBitflippingAttack;
import cryptopals.ciphers.Aes128CtrCipher;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class Challenge26CtrBitflippingTest {

    @Test
    void test() {
        var instance = new CtrBitflippingAttack(new Aes128CtrCipher());

        var forged = instance.forgeAdmin();

        assertTrue(instance.isAdmin(forged));
    }

}
