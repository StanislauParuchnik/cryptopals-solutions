package cryptopals;

import cryptopals.ciphers.Aes128CbcPkcs7Cipher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;

@RequiredArgsConstructor
@Slf4j
public class CbcBitflippingAttack {

    private final Aes128CbcPkcs7Cipher aes128CbcPkcs7Cipher;
    private final byte[] key;
    private final byte[] iv;

    public CbcBitflippingAttack(Aes128CbcPkcs7Cipher aes128CbcPkcs7Cipher) {
        this.aes128CbcPkcs7Cipher = aes128CbcPkcs7Cipher;
        key = Utils.randomBytes(Utils.AES_128_BLOCK_SIZE_IN_BYTES);
        iv = Utils.randomBytes(Utils.AES_128_BLOCK_SIZE_IN_BYTES);
    }

    public byte[] encryptInput(String str) {
        str = str.replace(";", "\\;")
                .replace("=", "\\=");

        str = "comment1=cooking%20MCs;userdata=" +
                str +
                ";comment2=%20like%20a%20pound%20of%20bacon";

        return aes128CbcPkcs7Cipher.encrypt(str.getBytes(StandardCharsets.UTF_8), iv, key);
    }

    public boolean isAdmin(byte[] encrypted) {
        var decrypted = new String(aes128CbcPkcs7Cipher.decrypt(encrypted, iv, key));
        log.debug(decrypted);

        return decrypted.contains(";admin=true;");
    }


    public byte[] forgeAdmin() {
        //encrypt blocks:
        // "comment1=cooking" "%20MCs;userdata=" "aaaaa|admin|true" ";comment2=%20lik"

        var str = "aaaaa|admin|true";

        var encrypted = encryptInput(str);

        //now patch encrypted block so that during decryption same changes are reflected in our input
        encrypted[Utils.AES_128_BLOCK_SIZE_IN_BYTES + 5] ^= '|' ^ ';';
        encrypted[Utils.AES_128_BLOCK_SIZE_IN_BYTES + 11] ^= '|' ^ '=';

        return encrypted;
    }

}
