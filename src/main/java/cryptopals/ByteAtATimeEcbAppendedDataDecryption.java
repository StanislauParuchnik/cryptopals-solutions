package cryptopals;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class ByteAtATimeEcbAppendedDataDecryption {

    private final ConsistentKeyEncryptionOracle encryptionOracle;

    public byte[] decryptAppendedText() {
        var sizes = determineSizes();
        log.debug(sizes.toString());
        var blockSize = sizes.blockSize();

        var appendedDataSize = sizes.appendedDataSize();
        var decryptedAppendedData = new byte[appendedDataSize];
        var bytesToFillPrefixBlock = sizes.prependedDataSizeInLastPrefixBlock == 0 ? 0 : blockSize - sizes.prependedDataSizeInLastPrefixBlock();
        var inputBlock = new byte[blockSize + bytesToFillPrefixBlock];

        int lastDecryptedByteIdx = 0;

        for (int decryptedBlockIdx = 0; decryptedBlockIdx < sizes.appendedDataTotalBlocks; ++decryptedBlockIdx) {
            for (int decryptedByteNumber = 1; decryptedByteNumber <= blockSize && lastDecryptedByteIdx < appendedDataSize; ++decryptedByteNumber) {
                var actualEncrypted = encryptionOracle.encrypt(inputBlock, inputBlock.length - decryptedByteNumber);
                for (int byteGuess = Byte.MIN_VALUE; byteGuess < Byte.MAX_VALUE; ++byteGuess) {
                    inputBlock[inputBlock.length - 1] = (byte) byteGuess;
                    var encrypted = encryptionOracle.encrypt(inputBlock);
                    if (Utils.areBlocksEqual(actualEncrypted,
                            (sizes.prependedDataTotalBlocks() + decryptedBlockIdx) * blockSize,
                            encrypted, sizes.prependedDataTotalBlocks() * blockSize, blockSize)) {

                        //found encrypted byte, save
                        decryptedAppendedData[lastDecryptedByteIdx++] = (byte) byteGuess;

                        //shift found bytes to previous position in input block
                        for (int i = bytesToFillPrefixBlock; i < inputBlock.length - 1; ++i) {
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
        //determine block size
        int padToFullBlockSize = 0;
        var input = new byte[1024];
        var encrypted = encryptionOracle.encrypt(input, padToFullBlockSize);
        var zeroInputEncryptionLen = encrypted.length;
        var encryptedLen = zeroInputEncryptionLen;

        while (encryptedLen == zeroInputEncryptionLen) {
            encrypted = encryptionOracle.encrypt(input, ++padToFullBlockSize);
            encryptedLen = encrypted.length;
        }

        var blockSize = encryptedLen - zeroInputEncryptionLen;
        validateECB(blockSize);

        //detect where prefix ends and appended data starts by changing input byte by byte
        var encryptedWithOnePlainTextBlock = encryptionOracle.encrypt(input, blockSize);
//        log.debug("encryptedWithOnePlainTextBlock:\n{}", Utils.toBlockHexString(encryptedWithOnePlainTextBlock, blockSize));
        input[0] = 1;
        var encryptedWithModifiedInput = encryptionOracle.encrypt(input, blockSize);
        input[0] = 0;
//        log.debug("encryptedWithModifiedInput:\n{}", Utils.toBlockHexString(encryptedWithOnePlainTextBlock, blockSize));
        var affectedBlockStart = 0;
        for (int i = 0; i < encryptedWithOnePlainTextBlock.length; i += blockSize) {
            if (!Utils.areBlocksEqual(encryptedWithOnePlainTextBlock, i,
                    encryptedWithModifiedInput, i,
                    blockSize)) {
                affectedBlockStart = i;
                break;
            }
        }

        int prependedDataSizeInLastPrefixBlock = 0;
        boolean affectecBlockChanged = false;
        for (int i = 1; i < blockSize; ++i) {
            input[i] = 1;
            encryptedWithModifiedInput = encryptionOracle.encrypt(input, blockSize);
            input[i] = 0;
            if (Utils.areBlocksEqual(
                    encryptedWithOnePlainTextBlock, affectedBlockStart,
                    encryptedWithModifiedInput, affectedBlockStart, blockSize) &&
                    !Utils.areBlocksEqual(
                            encryptedWithOnePlainTextBlock, affectedBlockStart + blockSize,
                            encryptedWithModifiedInput, affectedBlockStart + blockSize, blockSize)) {
                //affected block changed, now we know how much was appended to prefix block and where appended data block starts
                affectecBlockChanged = true;
                prependedDataSizeInLastPrefixBlock = blockSize - i;
                break;
            }
        }

        int prependedDataTotalBlocks = affectedBlockStart / blockSize + (affectecBlockChanged ? 1 : 0);
        var appendedDataSize = zeroInputEncryptionLen - padToFullBlockSize - affectedBlockStart - prependedDataSizeInLastPrefixBlock;

        return new DetermineSizesResult(
                blockSize,
                appendedDataSize,
                (appendedDataSize + 1) / (blockSize - 1),
                prependedDataSizeInLastPrefixBlock,
                prependedDataTotalBlocks
        );
    }

    private void validateECB(int blockSize) {
        var inputOf3blocks = new byte[blockSize * 3];
        var encrypted = encryptionOracle.encrypt(inputOf3blocks);
        if (!EcbDetector.isEcb(encrypted, blockSize)) {
            throw new RuntimeException("ECB not detected");
        }
    }

    private record DetermineSizesResult(
            int blockSize,
            int appendedDataSize,
            int appendedDataTotalBlocks,
            int prependedDataSizeInLastPrefixBlock,
            int prependedDataTotalBlocks
    ) {
    }

}
