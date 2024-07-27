package cryptopals.set5;

import cryptopals.dh.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Challenge35DHMaliciousGParamTest {

    static BigInteger p = new BigInteger(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
                    "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
                    "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
                    "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
                    "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
                    "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
                    "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
                    "fffffffffffff",
            16);

    @ParameterizedTest
    @MethodSource("maliciousGParams")
    public void testDHMaliciousGParam(BigInteger g) throws InterruptedException {
        var message = "Hello there!";

        var alice = ClientFactory.createClient("Alice");
        alice.addProtocolHandler(ClientAlgorithms.printEncryptedMessage());

        var bob = ClientFactory.createClient("Bob");
        bob.addProtocolHandler(ClientAlgorithms.echoEncryptedMessage());

        var wire = new Wire();
        ClientWireConnection.connect(alice, wire);
        ClientWireConnection.connect(bob, wire);

        var mallory = new MitmClient("Mallory");
        mallory.addMitmProtocolHandler(ClientAlgorithms.mitmDHMaliciousGProtocolHandler());
        mallory.addMitmProtocolHandler(ClientAlgorithms.mitmSniffEncryptedMessageHandler());

        MitmClientWireConnection.connect(mallory, wire);

        alice.start();
        bob.start();
        mallory.start();

        var dhCommand = ClientAlgorithms.initiateDHNegotiatedGroupCommand(bob.getName(), p, g);
        alice.runCommand(dhCommand);

        var sendMessageCommand = ClientAlgorithms.sendEncryptedMessage(bob.getName(), message);
        alice.runCommand(sendMessageCommand);


        var receivedMessage = (String) bob.subscribe(ProtocolHeader.ENCRYPTED_MESSAGE.name(), 5000);
        var echoedMessage = (String) alice.subscribe(ProtocolHeader.ENCRYPTED_MESSAGE.name(), 5000);
        var sniffedMessage = (String) mallory.subscribe(ProtocolHeader.ENCRYPTED_MESSAGE.name(), 5000);
        var echoedSniffedMessage = (String) mallory.subscribe(ProtocolHeader.ENCRYPTED_MESSAGE.name(), 5000);

        alice.stop();
        bob.stop();
        mallory.stop();

        assertEquals(message, receivedMessage);
        assertEquals(message, echoedMessage);
        assertEquals(message, sniffedMessage);
        assertEquals(message, echoedSniffedMessage);
    }


    private static Stream<Arguments> maliciousGParams() {
        return Stream.of(
                Arguments.of(BigInteger.ONE),
                Arguments.of(p),
                Arguments.of(p.subtract(BigInteger.ONE))
        );
    }

}
