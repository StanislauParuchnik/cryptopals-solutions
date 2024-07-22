package cryptopals.dh;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Data
public class Packet {
    private final String source;
    private final String destination;
    private final byte[] data;
}
