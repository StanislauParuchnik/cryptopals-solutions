package cryptopals;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class CbcPaddingOracleAttack {

    private final PaddingOracle paddingOracle;

    public byte[] decrypt(byte[] encrypted, byte[] iv) {
        var decrypted = new byte[encrypted.length];

        if (encrypted.length > Utils.AES_128_BLOCK_SIZE_IN_BYTES) {
            //decrypt all blocks except first
            var modifiedEncrypted = new byte[encrypted.length];

            for (int decryptedBlockStartIdx = encrypted.length - Utils.AES_128_BLOCK_SIZE_IN_BYTES;
                 decryptedBlockStartIdx >= Utils.AES_128_BLOCK_SIZE_IN_BYTES;
                 decryptedBlockStartIdx -= Utils.AES_128_BLOCK_SIZE_IN_BYTES) {
                System.arraycopy(encrypted, decryptedBlockStartIdx, modifiedEncrypted, decryptedBlockStartIdx, Utils.AES_128_BLOCK_SIZE_IN_BYTES);

                var modifiedEncryptedStartIdx = decryptedBlockStartIdx - Utils.AES_128_BLOCK_SIZE_IN_BYTES;

                for (int modifiedByteIdx = Utils.AES_128_BLOCK_SIZE_IN_BYTES - 1; modifiedByteIdx >= 0; --modifiedByteIdx) {
                    for (int cipherTextModifiedValue = 0; cipherTextModifiedValue < 256; ++cipherTextModifiedValue) {
                        modifiedEncrypted[modifiedEncryptedStartIdx + modifiedByteIdx] = (byte) cipherTextModifiedValue;
                        if (paddingOracle.isPaddingCorrect(iv, modifiedEncrypted, decryptedBlockStartIdx + Utils.AES_128_BLOCK_SIZE_IN_BYTES)) {
                            if (modifiedByteIdx == Utils.AES_128_BLOCK_SIZE_IN_BYTES - 1) {
                                //check edge case: if plain text block looks like xxxxxxxxxxxxxxxxxxxxxxxxxxxx02xx
                                //(or xxxxxxxxxxxxxxxxxxxxxxxxxx0303xx, xxxxxxxxxxxxxxxxxxxxxxxx040404xx, etc.)
                                //and our modified cipher text caused to decrypt to xxxxxxxxxxxxxxxxxxxxxxxxxxxx0202
                                //which is correct padding - we have to keep looking until we find such cipher text that
                                //block decrypts to xxxxxxxxxxxxxxxxxxxxxxxxxxxx0201

                                //This can be easily checked by changing penultimate cipherText
                                modifiedEncrypted[modifiedEncryptedStartIdx + modifiedByteIdx - 1] += 1;

                                var paddingCorrect = paddingOracle.isPaddingCorrect(iv, modifiedEncrypted,
                                        decryptedBlockStartIdx + Utils.AES_128_BLOCK_SIZE_IN_BYTES);
                                //if padding is still correct it matters that no matter what the value of penultimate is,
                                //it means that modified cipher text we just found caused to decrypt to
                                //xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx01, otherwise we have to keep looking
                                if (!paddingCorrect) {
                                    continue;
                                }

                                modifiedEncrypted[modifiedEncryptedStartIdx + modifiedByteIdx - 1] -= 1;

                            }
                            var paddingByteValue = Utils.AES_128_BLOCK_SIZE_IN_BYTES - modifiedByteIdx;

                            var keyStreamByteValue = paddingByteValue ^ modifiedEncrypted[modifiedEncryptedStartIdx + modifiedByteIdx];
                            var plainTextValue = keyStreamByteValue ^ encrypted[modifiedEncryptedStartIdx + modifiedByteIdx];
                            decrypted[decryptedBlockStartIdx + modifiedByteIdx] = (byte) plainTextValue;

                            byte paddingValueForNextIteration = (byte) (paddingByteValue ^ (paddingByteValue + 1));
                            Utils.xor(modifiedEncrypted, modifiedEncryptedStartIdx + modifiedByteIdx,
                                    paddingValueForNextIteration,
                                    Utils.AES_128_BLOCK_SIZE_IN_BYTES - modifiedByteIdx);
                            break;
                        }
                    }
                }
            }
        }

        //decrypt first block
        var modifiedIv = new byte[Utils.AES_128_BLOCK_SIZE_IN_BYTES];
        for (int modifiedByteIdx = Utils.AES_128_BLOCK_SIZE_IN_BYTES - 1; modifiedByteIdx >= 0; --modifiedByteIdx) {
            for (int cipherTextModifiedValue = 0; cipherTextModifiedValue < 256; ++cipherTextModifiedValue) {
                modifiedIv[modifiedByteIdx] = (byte) cipherTextModifiedValue;
                if (paddingOracle.isPaddingCorrect(modifiedIv, encrypted, Utils.AES_128_BLOCK_SIZE_IN_BYTES)) {
                    if (modifiedByteIdx == Utils.AES_128_BLOCK_SIZE_IN_BYTES - 1) {
                        //the same edge case check
                        modifiedIv[modifiedByteIdx - 1] += 1;

                        var paddingCorrect = paddingOracle.isPaddingCorrect(modifiedIv, encrypted, Utils.AES_128_BLOCK_SIZE_IN_BYTES);
                        if (!paddingCorrect) {
                            continue;
                        }
                        modifiedIv[modifiedByteIdx - 1] -= 1;
                    }

                    var paddingByteValue = Utils.AES_128_BLOCK_SIZE_IN_BYTES - modifiedByteIdx;

                    var keyStreamByteValue = paddingByteValue ^ modifiedIv[modifiedByteIdx];
                    var plainTextValue = keyStreamByteValue ^ iv[modifiedByteIdx];
                    decrypted[modifiedByteIdx] = (byte) plainTextValue;

                    byte paddingValueForNextIteration = (byte) (paddingByteValue ^ (paddingByteValue + 1));
                    Utils.xor(modifiedIv, modifiedByteIdx, paddingValueForNextIteration,
                            Utils.AES_128_BLOCK_SIZE_IN_BYTES - modifiedByteIdx);
                    break;
                }
            }
        }


        return PKCS7Padder.unPadBuffer(decrypted, Utils.AES_128_BLOCK_SIZE_IN_BYTES);
    }
}
