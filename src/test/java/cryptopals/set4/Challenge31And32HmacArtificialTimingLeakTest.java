package cryptopals.set4;

import cryptopals.ArtificialTimingLeakHmacSha1Cracker;
import cryptopals.ArtificialTimingLeakWebServer;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.function.UnaryOperator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Slf4j
@Disabled("disabled because one test takes around an hour to execute")
public class Challenge31And32HmacArtificialTimingLeakTest {

    @Test
    void test50msSleep() throws IOException, InterruptedException {
        run(8000, 50, x -> 2, 20);
    }

    @Test
    void test5msSleep() throws IOException, InterruptedException {
        run(8001, 5, x -> 10, 20);
    }

    @Test
    void test1msSleep() throws IOException, InterruptedException {
        run(8002, 1, x -> switch (x) {
                    //the further down cracking we go, the more fluctuations start adding up, so we need more executions
                    //for better results
                    case Integer i when i <= 7 -> 14;
                    case Integer i when i <= 10 -> 25;
                    case Integer i when i <= 13 -> 45;
                    case Integer i when i <= 17 -> 65;
                    default -> 85;
                }, 1000
        );
    }

    //the less is wait time, the more executions for a single byte are needed to get better average
    private void run(int port, long compareTimeoutMillis, UnaryOperator<Integer> numExecutionsresolver,
                     int warmUpNumExecutions)
            throws IOException, InterruptedException {
        run(port, compareTimeoutMillis, numExecutionsresolver, warmUpNumExecutions, null, 0);
    }

    //the less is wait time, the more executions for a single byte are needed to get better average
    private void run(int port, long compareTimeoutMillis, UnaryOperator<Integer> numExecutionsResolver,
                     int warmUpNumExecutions, byte[] startSignature, int startIdx)
            throws IOException, InterruptedException {
        log.info("Get yourself a coffee, expected time to crack is at least {}",
                calcExpectedWaitTimeMillis(compareTimeoutMillis, numExecutionsResolver, startIdx));

        var server = new ArtificialTimingLeakWebServer(port, compareTimeoutMillis);
        server.start();

        byte[] crackedSignature;
        var cracker = new ArtificialTimingLeakHmacSha1Cracker(numExecutionsResolver, warmUpNumExecutions);
        if (startSignature != null) {
            crackedSignature = cracker.crack(port, "file.txt", startSignature, startIdx);
        } else {
            crackedSignature = cracker.crack(port, "file.txt");

        }

        server.stop();

        assertNotNull(crackedSignature);
        var crackedSignatureHex = HexFormat.of().formatHex(crackedSignature);
        System.out.println(crackedSignatureHex);
        assertEquals("668a172f93492d21c3a75eca5afcb45d8243da9f", crackedSignatureHex);
    }

    private Duration calcExpectedWaitTimeMillis(long compareTimeoutMillis,
                                                UnaryOperator<Integer> numExecutionsResolver,
                                                int startIdx) {
        //just waits are calculated
        long expected = 0;

        for (int i = startIdx; i < 20; i++) {
            expected += (256 * i + 1) * compareTimeoutMillis * numExecutionsResolver.apply(i);
        }

        return Duration.ofMillis(expected);
    }
}
