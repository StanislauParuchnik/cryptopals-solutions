package cryptopals.set3;

import cryptopals.random.MT19937Rng;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.math3.random.MersenneTwister;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

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


    /**
     * File set3Challenge21.txt contains output from the following C++ program executed
     * online at <a href="https://www.cpp.sh/">https://www.cpp.sh/</a>:
     *
     * <pre><code>
     * #include &lt;iostream&gt;
     * #include &lt;random&gt;
     *
     * using namespace std;
     *
     * int main()
     * {
     *     mt19937 mt_rand(18345);
     *
     *     for (int i = 0; i < 10000; ++i)
     *     {
     *         cout << (int) mt_rand() << endl;
     *     }
     *
     *     return 0;
     * }
     * </code>
     * </pre>
     *
     *
     * @throws IOException
     */
    @Test
    void testAgainstCppMT19937() throws IOException {
        var cppRandomNumbers = Files.readAllLines(Paths.get("src\\test\\resources\\set3\\set3Challenge21.txt"));

        var myRng = new MT19937Rng(18345);

        cppRandomNumbers.stream()
                .mapToInt(Integer::valueOf)
                .forEach(cppRandomNumber -> assertEquals(myRng.nextInt(), cppRandomNumber));
    }
}
