package cryptopals.dh;

import java.util.concurrent.BlockingQueue;

public class MitmClientWireConnection extends ClientWireConnection {

    public MitmClientWireConnection(Client client, Wire wire, BlockingQueue<Packet> queue) {
        super(client, wire, queue);
    }

    boolean writeAs(ProtocolHeader protocol, String source, String destination, byte[] message) {
        var packet = new Packet(protocol, source, destination, message);
        return wire.forward(packet);
    }

    boolean forward(Packet packet) {
        return wire.forward(packet);
    }

    public static void connect(MitmClient client, Wire wire) {
        var queue = wire.connectManInTheMiddle(client.getName());
        var connection = new MitmClientWireConnection(client, wire, queue);
        client.setConnection(connection);
    }
}
