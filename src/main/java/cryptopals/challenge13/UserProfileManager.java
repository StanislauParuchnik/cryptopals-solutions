package cryptopals.challenge13;

import cryptopals.Utils;
import cryptopals.ciphers.Aes128EcbPkcs7Cipher;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.Collectors;

public class UserProfileManager {

    private final byte[] key;
    private final Aes128EcbPkcs7Cipher aes128EcbPkcs7Cipher;

    public UserProfileManager(Aes128EcbPkcs7Cipher aes128EcbPkcs7Cipher) {
        this.aes128EcbPkcs7Cipher = aes128EcbPkcs7Cipher;
        this.key = Utils.randomBytes(Utils.AES_128_BLOCK_SIZE_IN_BYTES);
    }

    public UserProfile profileFor(String email) {
        email = email.replace("[&=]", "");
        return new UserProfile(email, 10L, "user");
    }

    public UserProfile parseProfile(String profileEncoded) {
        var profileData = Arrays.stream(profileEncoded.split("&"))
                .map(s -> s.split("="))
                .collect(Collectors.toMap(s -> s[0], s -> s[1]));
        return new UserProfile(
                profileData.get("email"),
                Long.valueOf(profileData.get("uid")),
                profileData.get("role")
        );
    }

    public String encodeProfile(UserProfile userProfile) {
        return "email=" + userProfile.email() +
                "&uid=" + userProfile.uid() +
                "&role=" + userProfile.role();
    }

    public byte[] getEncryptedProfile(String email) {
        var profile = profileFor(email);
        var encodedProfile = encodeProfile(profile);
        return aes128EcbPkcs7Cipher.encrypt(encodedProfile.getBytes(StandardCharsets.UTF_8), key);
    }

    public UserProfile decryptProfile(byte[] encryptedProfile) {
        var decrypted = aes128EcbPkcs7Cipher.decrypt(encryptedProfile, key);
        return parseProfile(new String(decrypted));
    }
}
