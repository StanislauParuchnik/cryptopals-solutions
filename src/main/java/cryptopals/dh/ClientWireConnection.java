package cryptopals.dh;

import lombok.RequiredArgsConstructor;

import java.util.concurrent.BlockingQueue;

@RequiredArgsConstructor
public class ClientWireConnection {

    private final Client client;
    private final Wire wire;
    private final BlockingQueue<Packet> queue;

    public static void connect(Client client, Wire wire) {
        var queue = wire.connect(client);
        var connection = new ClientWireConnection(client, wire, queue);
        client.setConnection(connection);
    }

    Packet read() throws InterruptedException {
        return queue.take();
    }

    boolean write(String destination, byte[] message) {
        var packet = new Packet(client.getName(), destination, message);
        return wire.send(packet);
    }
}
