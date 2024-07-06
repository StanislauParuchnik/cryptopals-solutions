package cryptopals.set3;

import cryptopals.random.MT19937Rng;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.math3.random.MersenneTwister;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
public class Challenge21MT19937RngTest {

    @Test
    void testAgainstApacheMT19937() {
        var seed = 42;
        MersenneTwister apacheRng = new MersenneTwister(seed);
        var myRng = new MT19937Rng(seed);

        for (int i = 0; i < 100000; i++) {
            assertEquals(apacheRng.nextInt(), myRng.nextInt());
        }
    }
}
