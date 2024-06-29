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
                            var paddingByteValue = Utils.AES_128_BLOCK_SIZE_IN_BYTES - modifiedByteIdx;

                            var keyStreamByteValue = paddingByteValue ^ modifiedEncrypted[modifiedEncryptedStartIdx + modifiedByteIdx];
                            var plainTextValue = keyStreamByteValue ^ encrypted[modifiedEncryptedStartIdx + modifiedByteIdx];
                            decrypted[decryptedBlockStartIdx + modifiedByteIdx] = (byte) plainTextValue;

                            byte paddingValueForNextIteration = (byte) (paddingByteValue ^ (paddingByteValue + 1));
                            for (int i = modifiedByteIdx; i < Utils.AES_128_BLOCK_SIZE_IN_BYTES; ++i) {
                                modifiedEncrypted[modifiedEncryptedStartIdx + i] ^= paddingValueForNextIteration;
                            }
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
                    var paddingByteValue = Utils.AES_128_BLOCK_SIZE_IN_BYTES - modifiedByteIdx;

                    var keyStreamByteValue = paddingByteValue ^ modifiedIv[modifiedByteIdx];
                    var plainTextValue = keyStreamByteValue ^ iv[modifiedByteIdx];
                    decrypted[modifiedByteIdx] = (byte) plainTextValue;

                    byte paddingValueForNextIteration = (byte) (paddingByteValue ^ (paddingByteValue + 1));
                    for (int i = modifiedByteIdx; i < Utils.AES_128_BLOCK_SIZE_IN_BYTES; ++i) {
                        modifiedIv[i] ^= paddingValueForNextIteration;
                    }
                    break;
                }
            }
        }


        return PKCS7Padder.unPadBuffer(decrypted, Utils.AES_128_BLOCK_SIZE_IN_BYTES);
    }
}
