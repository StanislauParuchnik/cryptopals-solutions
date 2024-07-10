package cryptopals;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class RandomAccessReadWriteAesCtrCracker {

    private final Aes128RandomReadWriteEditor editor;

    public byte[] crack(byte[] encrypted) {
        var zeroPlainText = new byte[encrypted.length];
        var keyStream = editor.edit(encrypted, 0, zeroPlainText);
        return Utils.xor(encrypted, 0, keyStream, 0, encrypted.length);
    }
}
