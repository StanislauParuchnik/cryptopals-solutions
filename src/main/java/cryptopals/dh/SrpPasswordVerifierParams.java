package cryptopals.dh;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.math.BigInteger;

@Data
@AllArgsConstructor
public class SrpPasswordVerifierParams {
    private byte[] s;
    private BigInteger v;
}
