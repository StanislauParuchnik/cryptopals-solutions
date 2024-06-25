package cryptopals.set1;

import cryptopals.Utils;
import cryptopals.ciphers.Aes128EcbNoPaddingCipher;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
public class Challenge7AesECBDecryptTest {

    @Test
    void testDecrypt() throws IOException {
        var inputBytes = Utils.readBase64FromFile(Paths.get("src\\test\\resources\\set1\\set1Challenge7.txt"));

        var key = "YELLOW SUBMARINE";

        byte[] decryptedBytes = new Aes128EcbNoPaddingCipher().decrypt(inputBytes, key.getBytes(StandardCharsets.UTF_8));
        String decryptedString = new String(decryptedBytes);

        log.info(decryptedString);

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
                """, decryptedString);
    }

}
