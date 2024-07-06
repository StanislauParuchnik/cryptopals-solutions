package cryptopals.set1;

import cryptopals.SingleByteXorCipherCracker;
import cryptopals.Utils;
import cryptopals.ViginereCipherCracker;
import cryptopals.ciphers.VigenereCipher;
import cryptopals.metrics.FreqSquareDiffMetric;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
public class Challenge6ViginereCipherCrackerTest {

    @Test
    void testHammingDistance() {
        assertEquals(37,
                Utils.hammingDistanceBits(
                        "this is a test".getBytes(StandardCharsets.UTF_8),
                        "wokka wokka!!!".getBytes(StandardCharsets.UTF_8)
                )
        );
    }

    @Test
    void testCrack() throws IOException {
        var inputBytes = Utils.readBase64FromFile(Paths.get("src\\test\\resources\\set1\\set1Challenge6.txt"));

        var viginereCracker = createCracker();

        var result = viginereCracker.crackViginereCipher(inputBytes, 2, 40);

        log.info(result.toString());

        assertEquals("Terminator X: Bring the noise", new String(result.getKey()));

        assertEquals("""
                I'm back and I'm ringin' the bell\s
                A rockin' on the mike while the fly girls yell\s
                In ecstasy in the back of me\s
                Well that's my DJ Deshay cuttin' all them Z's\s
                Hittin' hard and the girlies goin' crazy\s
                Vanilla's on the mike, man I'm not lazy.\s
                                
                I'm lettin' my drug kick in\s
                It controls my mouth and I begin\s
                To just let it flow, let my concepts go\s
                My posse's to the side yellin', Go Vanilla Go!\s
                                
                Smooth 'cause that's the way I will be\s
                And if you don't give a damn, then\s
                Why you starin' at me\s
                So get off 'cause I control the stage\s
                There's no dissin' allowed\s
                I'm in my own phase\s
                The girlies sa y they love me and that is ok\s
                And I can dance better than any kid n' play\s
                                
                Stage 2 -- Yea the one ya' wanna listen to\s
                It's off my head so let the beat play through\s
                So I can funk it up and make it sound good\s
                1-2-3 Yo -- Knock on some wood\s
                For good luck, I like my rhymes atrocious\s
                Supercalafragilisticexpialidocious\s
                I'm an effect and that you can bet\s
                I can take a fly girl and make her wet.\s
                                
                I'm like Samson -- Samson to Delilah\s
                There's no denyin', You can try to hang\s
                But you'll keep tryin' to get my style\s
                Over and over, practice makes perfect\s
                But not if you're a loafer.\s
                                
                You'll get nowhere, no place, no time, no girls\s
                Soon -- Oh my God, homebody, you probably eat\s
                Spaghetti with a spoon! Come on and say it!\s
                                
                VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino\s
                Intoxicating so you stagger like a wino\s
                So punks stop trying and girl stop cryin'\s
                Vanilla Ice is sellin' and you people are buyin'\s
                'Cause why the freaks are jockin' like Crazy Glue\s
                Movin' and groovin' trying to sing along\s
                All through the ghetto groovin' this here song\s
                Now you're amazed by the VIP posse.\s
                                
                Steppin' so hard like a German Nazi\s
                Startled by the bases hittin' ground\s
                There's no trippin' on mine, I'm just gettin' down\s
                Sparkamatic, I'm hangin' tight like a fanatic\s
                You trapped me once and I thought that\s
                You might have it\s
                So step down and lend me your ear\s
                '89 in my time! You, '90 is my year.\s
                                
                You're weakenin' fast, YO! and I can tell it\s
                Your body's gettin' hot, so, so I can smell it\s
                So don't be mad and don't be sad\s
                'Cause the lyrics belong to ICE, You can call me Dad\s
                You're pitchin' a fit, so step back and endure\s
                Let the witch doctor, Ice, do the dance to cure\s
                So come up close and don't be square\s
                You wanna battle me -- Anytime, anywhere\s
                                
                You thought that I was weak, Boy, you're dead wrong\s
                So come on, everybody and sing this song\s
                                
                Say -- Play that funky music Say, go white boy, go white boy go\s
                play that funky music Go white boy, go white boy, go\s
                Lay down and boogie and play that funky music till you die.\s
                                
                Play that funky music Come on, Come on, let me hear\s
                Play that funky music white boy you say it, say it\s
                Play that funky music A little louder now\s
                Play that funky music, white boy Come on, Come on, Come on\s
                Play that funky music\s
                """, result.getDecryptedString());

    }

    @Test
    void testCrackKnownText1() {

        var input = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a262263242727" +
                "65272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

        var inputBytes = HexFormat.of().parseHex(input);

        var expected = "Burning 'em, if you ain't quick and nimble\n" +
                "I go crazy when I hear a cymbal";

        var viginereCracker = createCracker();
        //for short text try more keys
        viginereCracker.setAmountOfFirstKeyLengthToTry(6);

        var result = viginereCracker.crackViginereCipher(inputBytes, 2, 10);

        log.info(result.toString());
        assertEquals(expected, result.getDecryptedString());
        assertEquals("ICE", new String(result.getKey()));
    }

    @Test
    void textCrackKnownText2() {
        var inputText = new String("""
                "License" shall mean the terms and conditions for use, reproduction, and distribution as defined by Sections 1 through 9 of this document.
                                
                "Licensor" shall mean the copyright owner or entity authorized by the copyright owner that is granting the License.
                                
                "Legal Entity" shall mean the union of the acting entity and all other entities that control, are controlled by, or are under common control with that entity. For the purposes of this definition, "control" means (i) the power, direct or indirect, to cause the direction or management of such entity, whether by contract or otherwise, or (ii) ownership of fifty percent (50%) or more of the outstanding shares, or (iii) beneficial ownership of such entity.
                                
                "You" (or "Your") shall mean an individual or Legal Entity exercising permissions granted by this License.
                                
                "Source" form shall mean the preferred form for making modifications, including but not limited to software source code, documentation source, and configuration files.
                                
                "Object" form shall mean any form resulting from mechanical transformation or translation of a Source form, including but not limited to compiled object code, generated documentation, and conversions to other media types.
                                
                "Work" shall mean the work of authorship, whether in Source or Object form, made available under the License, as indicated by a copyright notice that is included in or attached to the work (an example is provided in the Appendix below).
                                
                "Derivative Works" shall mean any work, whether in Source or Object form, that is based on (or derived from) the Work and for which the editorial revisions, annotations, elaborations, or other modifications represent, as a whole, an original work of authorship. For the purposes of this License, Derivative Works shall not include works that remain separable from, or merely link (or bind by name) to the interfaces of, the Work and Derivative Works thereof."""
                .getBytes(StandardCharsets.UTF_8));
        var key = "This is a key";
        var encrypted = VigenereCipher.encrypt(
                inputText.getBytes(StandardCharsets.UTF_8),
                key.getBytes(StandardCharsets.UTF_8)
        );

        var cracker = createCracker();

        var result = cracker.crackViginereCipher(encrypted, 2, 40);

        log.info("Key: {}\nText: {}", result.getKey(), result.getDecryptedString());
        assertEquals(inputText, result.getDecryptedString());
    }

    private ViginereCipherCracker createCracker() {
        //don't check bigrams for single xor crack because text decrypted for key
        //element is not normal english text
        var xorMetric = new FreqSquareDiffMetric(1, 0);
        var singleXorCracker = new SingleByteXorCipherCracker(xorMetric);

        var metric = new FreqSquareDiffMetric();
        var viginereCracker = new ViginereCipherCracker(singleXorCracker, metric, 1);

        return viginereCracker;
    }
}
