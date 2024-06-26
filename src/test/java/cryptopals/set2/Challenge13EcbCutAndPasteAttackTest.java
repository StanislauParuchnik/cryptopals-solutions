package cryptopals.set2;

import cryptopals.challenge13.EcbCutAndPasteAttack;
import cryptopals.challenge13.UserProfileManager;
import cryptopals.ciphers.Aes128EcbPkcs7Cipher;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Challenge13EcbCutAndPasteAttackTest {

    @Test
    void test() {
        var userProfileManager = new UserProfileManager(
                new Aes128EcbPkcs7Cipher()
        );
        var cracker = new EcbCutAndPasteAttack(userProfileManager);

        var adminEncrypted = cracker.createEncryptedAdmin();
        var decryptedProfile = userProfileManager.decryptProfile(adminEncrypted);

        assertEquals("admin", decryptedProfile.role());
    }
}
