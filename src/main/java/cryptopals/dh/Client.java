package cryptopals.dh;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
public class Client {

    @Getter
    private final String name;

    @Setter
    private ClientWireConnection connection;

    @Getter
    private final Map<String, BigInteger> dhKeyMap = new HashMap<>();

    public void send(String destination, byte[] message) {
        var packet = new Packet(name, destination, message);
        connection.write(destination, message);
    }

    public Packet read() throws InterruptedException {
        return connection.read();
    }

}
