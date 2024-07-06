package cryptopals;

import lombok.RequiredArgsConstructor;

import java.util.List;

@RequiredArgsConstructor
public class FixedNonceCtrCracker {

    private final ViginereCipherCracker viginereCipherCracker;

    //it's possible to enhance by decrypt for all cipher texts, then remove least longest cipher text and decrypt for them
    //using already decrypted text to calculate text metric
    //then repeat until 2 cipher texts left
    public FixedNonceCtrCrackerResult breakFixedNonceCtr(List<byte[]> ciphertexts) {
        var minCiphertextLength = ciphertexts.stream()
                .mapToInt(arr -> arr.length)
                .min()
                .orElseThrow();

        var concatenatedCiphertexts = new byte[minCiphertextLength * ciphertexts.size()];

        for (int i = 0; i < ciphertexts.size(); i++) {
            System.arraycopy(ciphertexts.get(i), 0,
                    concatenatedCiphertexts, i * minCiphertextLength,
                    minCiphertextLength);
        }

        var crackResult = viginereCipherCracker.crackViginereCipher(concatenatedCiphertexts, minCiphertextLength,
                minCiphertextLength);

        var key = crackResult.getKey();

        var decrypted = ciphertexts.stream()
                .map(ct -> Utils.xor(ct, 0, key, 0, minCiphertextLength))
                .toList();

        return new FixedNonceCtrCrackerResult(decrypted, key);
    }

}
