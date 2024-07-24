package cryptopals.dh;

public class ClientFactory {

    public static Client createClient(String name) {
        var client = new Client(name);
        client.addProtocolHandler(DiffieHellman.dhProtocolHandler());

        return client;
    }
}
