package cryptopals;

import cryptopals.ciphers.Aes128CtrCipher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;

@RequiredArgsConstructor
@Slf4j
public class CtrBitflippingAttack {

    private final Aes128CtrCipher aes128CtrCipher;
    private final byte[] key;
    private final Long nonce;

    private final String prefix = "comment1=cooking%20MCs;userdata=";
    private final String suffix = ";comment2=%20like%20a%20pound%20of%20bacon";

    public CtrBitflippingAttack(Aes128CtrCipher aes128CtrCipher) {
        this.aes128CtrCipher = aes128CtrCipher;
        key = Utils.randomBytes(Utils.AES_128_BLOCK_SIZE_IN_BYTES);
        nonce = Utils.SECURE_RANDOM.nextLong();
    }

    public byte[] encryptInput(String str) {
        str = str.replace(";", "\\;")
                .replace("=", "\\=");

        str = prefix + str + suffix;

        return aes128CtrCipher.apply(str.getBytes(StandardCharsets.UTF_8), key, nonce);
    }

    public boolean isAdmin(byte[] encrypted) {
        var decrypted = new String(aes128CtrCipher.apply(encrypted, key, nonce));
        log.debug(decrypted);

        return decrypted.contains(";admin=true;");
    }


    public byte[] forgeAdmin() {
        //encrypt data:
        // "comment1=cooking%20MCs;userdata=aa|admin|true;comment2=%20li....."

        var str = "aa|admin|true";

        var encrypted = encryptInput(str);

        //now patch encrypted block so that during decryption same changes are reflected in our input
        encrypted[prefix.length() + 2] ^= '|' ^ ';';
        encrypted[prefix.length() + 8] ^= '|' ^ '=';

        return encrypted;
    }


}
