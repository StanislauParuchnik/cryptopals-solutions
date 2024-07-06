package cryptopals.set3;

import cryptopals.Mt199937Cloner;
import cryptopals.random.MT19937Rng;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Challenge23CloneMT199937StateTest {

    @Test
    void test() {
        var rng = new MT19937Rng(4554312);

        var cloner = new Mt199937Cloner();

        var clonedRnd = cloner.clone(rng);

        for (int i = 0; i < 1000; i++) {
            assertEquals(rng.nextInt(), clonedRnd.nextInt());
        }
    }
}
