package cryptopals;

import cryptopals.ciphers.RsaPublicKey;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.List;

public class RSAEeq3BroadcastAttack {

    public static byte[] crackPlainText(List<byte[]> encrypted, List<RsaPublicKey> keys) {
        //we need as much encrypted messages as 'e' so that it's possible to
        //calculate 'e'-th root of m ** e (which is m) after solving CRT equations:
        //Since m < N_i then m ** e < N_1 * N_2 * ... N_e and we can just calculate non-modular (simple) 'e'-th root,
        //where m is plaintext

        //this implementation is for e = 3
        int supportedPublicExponent = 3;

        if (!keys.stream().allMatch(k -> k.e().equals(BigInteger.valueOf(supportedPublicExponent)))) {
            throw new IllegalArgumentException("Public exponent must be " + supportedPublicExponent + " for this attack");
        }

        if (encrypted.size() != supportedPublicExponent && keys.size() != supportedPublicExponent) {
            throw new IllegalArgumentException("Invalid number of encrypted data");
        }

        var c = encrypted.stream().map(BigInteger::new).toList();
        var n = keys.stream().map(RsaPublicKey::n).toList();

        if (new HashSet<>(n).size() != 3) {
            throw new IllegalArgumentException("Keys must be different");
        }

        var r = Utils.solveCRT(c, n);
        var root = Utils.cubeRoot(r);

        if (root == null) {
            return null;
        }
        return root.toByteArray();
    }
}
