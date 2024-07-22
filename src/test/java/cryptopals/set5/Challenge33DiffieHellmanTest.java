package cryptopals.set5;

import cryptopals.dh.Client;
import cryptopals.dh.ClientWireConnection;
import cryptopals.dh.DiffieHellman;
import cryptopals.dh.Wire;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Slf4j
public class Challenge33DiffieHellmanTest {

    @Test
    void testDH1() throws InterruptedException {
        testDH(BigInteger.valueOf(37), BigInteger.valueOf(5));
    }

    @Test
    void testDH2() throws InterruptedException {
        var p = new BigInteger(
                "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
                        "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
                        "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
                        "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
                        "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
                        "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
                        "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
                        "fffffffffffff",
                16);
        var g = BigInteger.TWO;


        testDH(p, g);
    }


    void testDH(BigInteger p, BigInteger g) throws InterruptedException {
        var alice = new Client("Alice");
        var bob = new Client("Bob");
        var wire = new Wire();
        ClientWireConnection.connect(alice, wire);
        ClientWireConnection.connect(bob, wire);

        var aliceThread = DiffieHellman.DHInitiatorThread(alice, bob.getName(), p, g);
        var bobThread = DiffieHellman.DHReceiverThread(bob, p, g);

        aliceThread.start();
        bobThread.start();

        aliceThread.join();
        bobThread.join();


        assertTrue(alice.getDhKeyMap().containsKey(bob.getName()));
        assertTrue(bob.getDhKeyMap().containsKey(alice.getName()));
        assertEquals(alice.getDhKeyMap().get(bob.getName()), bob.getDhKeyMap().get(alice.getName()));
    }

}
