package cryptopals.set5;

import cryptopals.dh.*;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Challenge36SecureRemotePasswordTest {

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

    BigInteger k = BigInteger.valueOf(3);

    @Test
    void testSRPRegistration() throws Exception {
        var srpClient = new Client("Carol");
        var userName = "carol@mymail.com";
        var password = "carolBestPassword";

        var srpServer = new Client("Steeve");
        srpServer.addProtocolHandler(ClientAlgorithms.registerSRPServer(p, g, k));

        var wire = new Wire();

        ClientWireConnection.connect(srpClient, wire);
        ClientWireConnection.connect(srpServer, wire);

        srpClient.runCommand(ClientAlgorithms.registerSRPClient(srpServer.getName(), userName, password, p, g, k));

        srpServer.start();
        srpClient.start();


        var registeredClient = srpServer.subscribe(ProtocolHeader.SRP_REGISTER.name(), 1000);

        assertEquals(srpClient.getName(), registeredClient);

        srpServer.stop();
        srpClient.stop();
    }

    @Test
    void testSRPAuth() throws Exception {
        var srpClient = new Client("Carol");
        var userName = "carol@mymail.com";
        var password = "carolBestPassword";

        var srpServer = new Client("Steeve");
        srpServer.addProtocolHandler(ClientAlgorithms.registerSRPServer(p, g, k));
        srpServer.addProtocolHandler(ClientAlgorithms.authSRPClientServerHandler(p, g, k));

        var wire = new Wire();

        ClientWireConnection.connect(srpClient, wire);
        ClientWireConnection.connect(srpServer, wire);

        srpServer.start();
        srpClient.start();

        srpClient.runCommand(ClientAlgorithms.registerSRPClient(srpServer.getName(), userName, password, p, g, k));
        var registeredClient = srpServer.subscribe(ProtocolHeader.SRP_REGISTER.name(), 1000);

        System.out.println();

        srpClient.runCommand(ClientAlgorithms.authSRPClient(srpServer.getName(), userName, password, p, g, k));

        var clientAuthValue = srpClient.subscribe(ProtocolHeader.SRP.name(), 5000);
        var serverAuthValue = srpServer.subscribe(ProtocolHeader.SRP.name(), 5000);

        srpServer.stop();
        srpClient.stop();


        assertEquals(srpClient.getName(), registeredClient);
        assertEquals(srpServer.getName() + ": OK", clientAuthValue);
        assertEquals(srpClient.getName() + ": OK", serverAuthValue);
    }
}
