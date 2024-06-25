package cryptopals;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class Challenge12ByteAtATimeEcbDecryption {

    private final Challenge12Encryptor encryptor;

    public byte[] decryptAppendedText() {
        var sizes = determineSizes();
        var blockSize = sizes.blockSize();
        validateECB(blockSize);

        var appendedDataSize = sizes.appendedDataSize();
        var decryptedAppendedData = new byte[appendedDataSize];
        var inputBlock = new byte[blockSize];

        int lastDecryptedByteIdx = 0;

        var decryptedBlocksNumber = sizes.emptyInputEncryptedBlocksNumber;
        for (int decryptedBlockIdx = 0; decryptedBlockIdx < decryptedBlocksNumber; ++decryptedBlockIdx) {
            for (int decryptedByteNumber = 1; decryptedByteNumber <= blockSize && lastDecryptedByteIdx < appendedDataSize; ++decryptedByteNumber) {
                var actualEncrypted = encryptor.encrypt(inputBlock, blockSize - decryptedByteNumber);
                for (int byteGuess = Byte.MIN_VALUE; byteGuess < Byte.MAX_VALUE; ++byteGuess) {
                    inputBlock[blockSize - 1] = (byte) byteGuess;
                    var encrypted = encryptor.encrypt(inputBlock);
                    if (Utils.areBlocksEqual(actualEncrypted, decryptedBlockIdx * blockSize,
                            encrypted, 0, blockSize)) {

                        //found encrypted byte, save
                        decryptedAppendedData[lastDecryptedByteIdx++] = (byte) byteGuess;

                        //shift found bytes to previous position in input block
                        for (int i = 0; i < blockSize - 1; ++i) {
                            inputBlock[i] = inputBlock[i + 1];
                        }

                        break;
                    }
                }
            }
        }

        return decryptedAppendedData;
    }

    private DetermineSizesResult determineSizes() {
        int inputSize = 0;
        var input = new byte[1024];
        var encrypted = encryptor.encrypt(input, inputSize);
        var initialEncryptedLen = encrypted.length;
        var encryptedLen = initialEncryptedLen;

        while (encryptedLen == initialEncryptedLen) {
            encrypted = encryptor.encrypt(input, ++inputSize);
            encryptedLen = encrypted.length;
        }

        var blockSize = encryptedLen - initialEncryptedLen;
        return new DetermineSizesResult(
                encryptedLen - initialEncryptedLen,
                initialEncryptedLen - inputSize,
                initialEncryptedLen / blockSize
        );
    }

    private void validateECB(int blockSize) {
        var inputOf2blocks = new byte[blockSize * 2];
        var encrypted = encryptor.encrypt(inputOf2blocks);
        if (!EcbDetector.isEcb(encrypted, blockSize)) {
            throw new RuntimeException("ECB not detected");
        }
    }

    private record DetermineSizesResult(
            int blockSize,
            int appendedDataSize,
            int emptyInputEncryptedBlocksNumber
    ) {
    }

}
