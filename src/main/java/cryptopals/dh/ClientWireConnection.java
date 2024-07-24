package cryptopals.dh;

import lombok.RequiredArgsConstructor;

import java.util.concurrent.BlockingQueue;

@RequiredArgsConstructor
public class ClientWireConnection {

    protected final Client client;
    protected final Wire wire;
    protected final BlockingQueue<Packet> queue;

    public static void connect(Client client, Wire wire) {
        var queue = wire.connect(client.getName());
        var connection = new ClientWireConnection(client, wire, queue);
        client.setConnection(connection);
    }

    Packet read() throws InterruptedException {
        return queue.take();
    }

    Packet tryRead() throws InterruptedException {
        return queue.poll();
    }

    boolean write(ProtocolHeader header, String destination, byte[] message) {
        var packet = new Packet(header, client.getName(), destination, message);
        return wire.send(packet);
    }
}
