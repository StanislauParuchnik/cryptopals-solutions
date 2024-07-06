package cryptopals;

import cryptopals.random.MT19937Rng;

import java.util.Optional;

public class MT19937RngSeedCracker {

    private int maxAttempts = 5000;

    public Optional<Integer> crackSeed(int firstRandomNumber) {
        int unixTimestamp = (int) (System.currentTimeMillis() / 1000);
        var rng = new MT19937Rng(unixTimestamp);

        for (int seed = unixTimestamp; seed > maxAttempts; seed--) {
            rng.setSeed(seed);
            var randomNumber = rng.nextInt();
            if (randomNumber == firstRandomNumber) {
                return Optional.of(seed);
            }
        }

        return Optional.empty();
    }


}
