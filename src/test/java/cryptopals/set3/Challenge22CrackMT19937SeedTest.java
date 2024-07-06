package cryptopals.set3;

import cryptopals.MT19937RngSeedCracker;
import cryptopals.random.MT19937Rng;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Random;

import static java.util.Map.entry;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Slf4j
public class Challenge22CrackMT19937SeedTest {

    //wait when testing this attack specifically, otherwise won't wait
    private static final boolean WAIT = false;

    @Test
    public void test() throws InterruptedException {
        var seedAndRandomNumber = generateRandomNumber(40, 1000);
        var seed = seedAndRandomNumber.getKey();
        var randomNumber = seedAndRandomNumber.getValue();

        var seedCracker = new MT19937RngSeedCracker();
        var crackedSeed = seedCracker.crackSeed(randomNumber);

        assertTrue(crackedSeed.isPresent());
        assertEquals(seed, crackedSeed.get());
    }

    private Map.Entry<Integer, Integer> generateRandomNumber(int minSecondsWait, int maxSecondsWait) throws InterruptedException {
        var randomSecondsGenerator = new Random();
        int unixTimeStamp;
        int randomNumber;

        if (WAIT) {
            int waitSeconds = randomSecondsGenerator.nextInt(minSecondsWait, maxSecondsWait);
            log.info("Waiting for {} seconds", waitSeconds);
            Thread.sleep(waitSeconds * 1000);
            log.info("Waiting complete");

            unixTimeStamp = (int) (System.currentTimeMillis() / 1000);
            var rng = new MT19937Rng(unixTimeStamp);
            randomNumber = rng.nextInt();

            waitSeconds = randomSecondsGenerator.nextInt(minSecondsWait, maxSecondsWait);
            log.info("Waiting for {} seconds", waitSeconds);
            Thread.sleep(waitSeconds * 1000);
            log.info("Waiting complete");
        } else {
            int waitSeconds = randomSecondsGenerator.nextInt(40, 1000);

            // pretend that number was generated in the past
            unixTimeStamp = (int) (System.currentTimeMillis() / 1000) - waitSeconds;

            var rng = new MT19937Rng(unixTimeStamp);
            randomNumber = rng.nextInt();
        }

        return entry(unixTimeStamp, randomNumber);
    }
}
