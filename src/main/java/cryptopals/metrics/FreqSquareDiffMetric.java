package cryptopals.metrics;

import java.util.HashMap;
import java.util.Map;

public class FreqSquareDiffMetric implements TextMetric {

    static final Map<Character, Double> englishLettersFrequency = new HashMap<>();
    static final Map<String, Double> englishCommmonBigrams = new HashMap<>();

    static final double DEFAULT_LETTER_WEIGHT = 0.6;
    static final double DEFAULT_BIGRAM_WEIGHT = 0.4;

    private final double letterWeight;
    private final double bigramWeight;

    static {
        englishLettersFrequency.put('E', 0.111607);
        englishLettersFrequency.put('A', 0.084966);
        englishLettersFrequency.put('R', 0.075809);
        englishLettersFrequency.put('I', 0.075448);
        englishLettersFrequency.put('O', 0.071635);
        englishLettersFrequency.put('T', 0.069509);
        englishLettersFrequency.put('N', 0.066544);
        englishLettersFrequency.put('S', 0.057351);
        englishLettersFrequency.put('L', 0.054893);
        englishLettersFrequency.put('C', 0.045388);
        englishLettersFrequency.put('U', 0.036308);
        englishLettersFrequency.put('D', 0.033844);
        englishLettersFrequency.put('P', 0.031671);
        englishLettersFrequency.put('M', 0.030129);
        englishLettersFrequency.put('H', 0.030034);
        englishLettersFrequency.put('G', 0.024705);
        englishLettersFrequency.put('B', 0.020720);
        englishLettersFrequency.put('F', 0.018121);
        englishLettersFrequency.put('Y', 0.017779);
        englishLettersFrequency.put('W', 0.012899);
        englishLettersFrequency.put('K', 0.011016);
        englishLettersFrequency.put('V', 0.010074);
        englishLettersFrequency.put('X', 0.002902);
        englishLettersFrequency.put('Z', 0.002722);
        englishLettersFrequency.put('J', 0.001965);
        englishLettersFrequency.put('Q', 0.001962);

        englishCommmonBigrams.put("TH", 0.03);
        englishCommmonBigrams.put("HE", 0.03);
        englishCommmonBigrams.put("IN", 0.02);
        englishCommmonBigrams.put("ER", 0.02);
        englishCommmonBigrams.put("AN", 0.02);
        englishCommmonBigrams.put("RE", 0.01);
        englishCommmonBigrams.put("ND", 0.01);
        englishCommmonBigrams.put("ON", 0.01);
        englishCommmonBigrams.put("EN", 0.01);
        englishCommmonBigrams.put("AT", 0.01);
        englishCommmonBigrams.put("OU", 0.01);
        englishCommmonBigrams.put("ED", 0.01);
        englishCommmonBigrams.put("HA", 0.01);
        englishCommmonBigrams.put("TO", 0.01);
        englishCommmonBigrams.put("OR", 0.01);
        englishCommmonBigrams.put("IT", 0.01);
        englishCommmonBigrams.put("IS", 0.01);
        englishCommmonBigrams.put("HI", 0.01);
        englishCommmonBigrams.put("ES", 0.01);
        englishCommmonBigrams.put("NG", 0.01);
    }

    public FreqSquareDiffMetric() {
        this(DEFAULT_LETTER_WEIGHT, DEFAULT_BIGRAM_WEIGHT);
    }

    public FreqSquareDiffMetric(double letterWeight, double bigramWeight) {
        this.letterWeight = letterWeight;
        this.bigramWeight = bigramWeight;
    }

    @Override
    public double calculateMetric(String text) {
        text = text.toUpperCase();


        var letterCounts = new HashMap<Character, Integer>();
        var nonLetterCount = 0;
        var nonLetterAllowedCount = 0;
        var bigramCounts = new HashMap<String, Integer>();
        var nonCommonBigramCount = 0;
        for (int i = 0; i < text.length(); i++) {
            var letter = text.charAt(i);

            //singleLetter
            if (!Character.isDefined(letter)) {
                return Double.MAX_VALUE;
            }
            if (Character.isLetter(letter)) {
                letterCounts.compute(letter, (c, v) -> v == null ? 1 : ++v);
            } else {
                if (!Character.isDigit(letter) &&
                        !Character.isWhitespace(letter) &&
                        !Character.isAlphabetic(letter)) {
                    nonLetterCount++;
                } else {
                    nonLetterAllowedCount++;
                }
            }

            //bigrams
            if (i + 1 < text.length()) {
                var bigram = text.substring(i, i + 2);
                if (englishCommmonBigrams.containsKey(bigram)) {
                    bigramCounts.compute(bigram, (b, v) -> v == null ? 1 : ++v);
                } else {
                    nonCommonBigramCount++;
                }
            }
        }

        double letterFreqMetric = 0;
        for (var character : englishLettersFrequency.keySet()) {
            var diff = englishLettersFrequency.get(character) -
                    ((double) letterCounts.getOrDefault(character, 0) / (text.length() - nonLetterAllowedCount));
            letterFreqMetric += diff * diff;
        }
        var nonLetterFreq = (double) nonLetterCount / (text.length() - nonLetterAllowedCount);
        letterFreqMetric += nonLetterFreq * nonLetterFreq;

        double bigramFreqMetric = 0;
        for (var bigram : englishCommmonBigrams.keySet()) {
            var diff = englishCommmonBigrams.get(bigram) -
                    ((double) bigramCounts.getOrDefault(bigram, 0) / (text.length() - 1));
            bigramFreqMetric = diff * diff;
        }
        var nonCommonBigramFreq = (double) nonCommonBigramCount / (text.length() - 1);
        bigramFreqMetric += nonCommonBigramFreq * nonCommonBigramFreq;

        return letterWeight * letterFreqMetric +
                bigramWeight * bigramFreqMetric;
    }
}
