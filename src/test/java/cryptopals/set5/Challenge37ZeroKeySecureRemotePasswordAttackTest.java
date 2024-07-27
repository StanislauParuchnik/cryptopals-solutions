package cryptopals.set5;

import cryptopals.dh.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Challenge37ZeroKeySecureRemotePasswordAttackTest {

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

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 3, 4})
    void testSRPAuthByPassWithZeroKey(int nMultiple) throws Exception {
        var srpClient = new Client("Carol");
        var userName = "carol@mymail.com";
        var password = "carolBestPassword";

        var srpServer = new Client("Steeve");
        srpServer.addProtocolHandler(ClientAlgorithms.registerSRPServer(p, g, k));
        srpServer.addProtocolHandler(ClientAlgorithms.authSRPClientServerHandler(p, g, k));

        var mallory = new Client("Mallory");

        var wire = new Wire();

        ClientWireConnection.connect(srpClient, wire);
        ClientWireConnection.connect(srpServer, wire);
        ClientWireConnection.connect(mallory, wire);

        srpServer.start();
        srpClient.start();
        mallory.start();

        srpClient.runCommand(ClientAlgorithms.registerSRPClient(srpServer.getName(), userName, password, p, g, k));
        var registeredUser = srpServer.subscribe(ProtocolHeader.SRP_REGISTER.name(), 1000);

        System.out.println();

        mallory.runCommand(ClientAlgorithms.authSRPClientBypassZeroKey(srpServer.getName(), userName, nMultiple, p, g, k));

        var malloryAuthValue = mallory.subscribe(ProtocolHeader.SRP.name(), 5000);
        var serverAuthValue = srpServer.subscribe(ProtocolHeader.SRP.name(), 5000);

        srpServer.stop();
        srpClient.stop();
        mallory.stop();


        assertEquals(userName, registeredUser);
        assertEquals(srpServer.getName() + ": OK", malloryAuthValue);
        assertEquals(mallory.getName() + ": OK", serverAuthValue);
    }
}
