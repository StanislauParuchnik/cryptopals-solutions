package cryptopals.set5;

import cryptopals.dh.*;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Challenge38SimplifiedSRPOfflineDictionaryAttackTest {

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

    BigInteger g = BigInteger.TWO;

    @Test
    void testSimplifiedSRPAuth() throws Exception {
        var srpClient = new Client("Carol");
        var userName = "carol@mymail.com";

        var password = "carolBestPassword";

        var srpServer = new Client("Steeve");
        srpServer.addProtocolHandler(ClientAlgorithms.registerSRPServer());
        srpServer.addProtocolHandler(ClientAlgorithms.authSimplifiedSRPClientServerHandler(p, g));

        var wire = new Wire();

        ClientWireConnection.connect(srpClient, wire);
        ClientWireConnection.connect(srpServer, wire);

        srpServer.start();
        srpClient.start();

        srpClient.runCommand(ClientAlgorithms.registerSRPClient(srpServer.getName(), userName, password, p, g));
        var registeredUser = srpServer.subscribe(ProtocolHeader.SRP_REGISTER.name(), 1000);

        System.out.println();

        srpClient.runCommand(ClientAlgorithms.authSimplifiedSRPClient(srpServer.getName(), userName, password, p, g));

        var clientAuthValue = srpClient.subscribe(ProtocolHeader.SRP_SIMPLIFIED.name(), 5000);
        var serverAuthValue = srpServer.subscribe(ProtocolHeader.SRP_SIMPLIFIED.name(), 5000);

        srpServer.stop();
        srpClient.stop();


        assertEquals(userName, registeredUser);
        assertEquals(srpServer.getName() + ": OK", clientAuthValue);
        assertEquals(srpClient.getName() + ": OK", serverAuthValue);
    }


    @Test
    void testSimplifiedSRPAuthOfflineDictionaryAttack() throws Exception {
        var dictionary = Paths.get("src\\test\\resources\\set5\\dictionary.txt");
        var srpClient = new Client("Carol");
        var userName = "carol@mymail.com";

        var words = Files.readAllLines(dictionary);
        //pick among first 500 just for faster test execution
        var password = words.get(new Random().nextInt(Math.min(words.size(), 500)));

        var srpServer = new Client("Steeve");
        srpServer.addProtocolHandler(ClientAlgorithms.registerSRPServer());
        srpServer.addProtocolHandler(ClientAlgorithms.authSimplifiedSRPClientServerHandler(p, g));

        var mallory = new MitmClient("Mallory");
        mallory.addMitmProtocolHandler(ClientAlgorithms.authSimplifiedSRPClientMitmDictionaryAttackHandler(p, g, dictionary));

        var wire = new Wire();

        ClientWireConnection.connect(srpClient, wire);
        ClientWireConnection.connect(srpServer, wire);
        MitmClientWireConnection.connect(mallory, wire);

        srpServer.start();
        srpClient.start();
        mallory.start();

        srpClient.runCommand(ClientAlgorithms.registerSRPClient(srpServer.getName(), userName, password, p, g));
        var registeredUser = srpServer.subscribe(ProtocolHeader.SRP_REGISTER.name(), 1000);

        System.out.println();

        srpClient.runCommand(ClientAlgorithms.authSimplifiedSRPClient(srpServer.getName(), userName, password, p, g));

        Thread.sleep(2);

        var clientAuthValue = srpClient.subscribe(ProtocolHeader.SRP_SIMPLIFIED.name(), 5000);
        var crackedPasswordValue = mallory.subscribe(ProtocolHeader.SRP_SIMPLIFIED.name(), 600000);

        srpServer.stop();
        srpClient.stop();
        mallory.stop();

        assertEquals(userName, registeredUser);
        assertEquals(srpServer.getName() + ": OK", clientAuthValue);
        assertEquals(srpClient.getName() + " password: " + password, crackedPasswordValue);
    }
}
