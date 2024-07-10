package cryptopals;

import cryptopals.ciphers.Aes128CtrCipher;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class Aes128RandomReadWriteEditor {
    private final Aes128CtrCipher aes128CtrCipher = new Aes128CtrCipher();
    private final byte[] key;
    private final long nonce;


    public byte[] edit(byte[] encrypted, int offset, byte[] newData) {
        var decrypted = aes128CtrCipher.apply(encrypted, key, nonce);
        var modifiedData = editPlaintextData(decrypted, offset, newData);

        //better implementation would be to skip generation of first 'offset' keyStream elements during re-encryption,
        //but that's just optimization and isn't important for the idea of cracking
        return aes128CtrCipher.apply(modifiedData, key, nonce);
    }

    private byte[] editPlaintextData(byte[] decrypted, int offset, byte[] newData) {
        var modifiedData = new byte[Math.max(newData.length + offset, decrypted.length)];

        if (offset > 0) {
            System.arraycopy(decrypted, 0, modifiedData, 0, offset);
        }
        System.arraycopy(newData, 0, modifiedData, offset, newData.length);
        if (newData.length + offset < decrypted.length) {
            System.arraycopy(decrypted, newData.length + offset,
                    modifiedData, newData.length + offset, decrypted.length - offset - newData.length);
        }
        return modifiedData;
    }
}
