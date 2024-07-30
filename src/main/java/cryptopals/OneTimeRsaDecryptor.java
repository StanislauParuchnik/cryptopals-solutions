package cryptopals;

import cryptopals.ciphers.RsaCipher;
import cryptopals.ciphers.RsaPrivateKey;
import lombok.RequiredArgsConstructor;

import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;

@RequiredArgsConstructor
public class OneTimeRsaDecryptor {

    private final Set<String> decryptedHashes = new HashSet<>();
    private final RsaCipher rsaCipher;
    private final RsaPrivateKey privateKey;

    public byte[] decrypt(byte[] input) throws NoSuchAlgorithmException {
        var hash = HexFormat.of().formatHex(Utils.SHA256(input));
        if (decryptedHashes.contains(hash)) {
            throw new IllegalArgumentException("Input was already decrypted");
        }
        var result = rsaCipher.apply(input, privateKey);
        decryptedHashes.add(hash);
        return result;
    }
}
