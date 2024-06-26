package cryptopals.challenge13;

import cryptopals.Utils;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class EcbCutAndPasteAttack {

    private final UserProfileManager userProfileManager;

    public byte[] createEncryptedAdmin() {
        //craft email so that the following is encrypted (separated by blocks):
        // "email=aaaaa@foo." | "bar&uid=10&role=" | "user"
        var craftedEmail = "aaaaa@foo.bar";

        var encryptedCraftedEmail = userProfileManager.getEncryptedProfile(craftedEmail);

        //next encrypt "admin" with padding
        // "email=aaaaa@foo." | "admin\x11\x11\x11\x11..." | "&uid=10&role=use" | "r"

        var craftedEmailForAdmin = "aaaaa@foo.admin\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000b";
        var encryptedPaddedAdmin = userProfileManager.getEncryptedProfile(craftedEmailForAdmin);

        //now combine first 2 blocks from email and second block from admin
        var result = new byte[Utils.AES_128_BLOCK_SIZE_IN_BYTES * 3];
        System.arraycopy(encryptedCraftedEmail, 0, result, 0, Utils.AES_128_BLOCK_SIZE_IN_BYTES * 2);
        System.arraycopy(encryptedPaddedAdmin, Utils.AES_128_BLOCK_SIZE_IN_BYTES,
                result, Utils.AES_128_BLOCK_SIZE_IN_BYTES * 2, Utils.AES_128_BLOCK_SIZE_IN_BYTES);

        return result;
    }
}
