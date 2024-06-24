package cryptopals.set1;

import cryptopals.FixedXOR;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Challenge2FixedXORTest {

    @Test
    void test() {
        assertEquals("746865206b696420646f6e277420706c6179",
                FixedXOR.fixedXorHex(
                        "1c0111001f010100061a024b53535009181c",
                        "686974207468652062756c6c277320657965")
        );
    }
}
