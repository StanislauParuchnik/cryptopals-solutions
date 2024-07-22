package cryptopals.dh;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class Wire {

    private final Map<String, BlockingQueue<Packet>> queueMap = new HashMap<>();

    BlockingQueue<Packet> connect(Client client) {
        if (queueMap.containsKey(client.getName())) {
            throw new RuntimeException("Client already connected: " + client.getName());
        }

        var queue = new LinkedBlockingQueue<Packet>();
        queueMap.put(client.getName(), queue);
        return queue;
    }

    public boolean send(Packet packet) {
        if (queueMap.containsKey(packet.getDestination())) {
            return queueMap.get(packet.getDestination()).offer(packet);
        }
        throw new RuntimeException("Destination does not exist: " + packet.getDestination());
    }
}
