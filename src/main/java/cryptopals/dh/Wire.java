package cryptopals.dh;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class Wire {

    private final Map<String, BlockingQueue<Packet>> queueMap = new HashMap<>();
    private String manInTheMiddleName;
    private BlockingQueue<Packet> manInTheMiddleQueue;

    BlockingQueue<Packet> connect(String clientName) {
        if (queueMap.containsKey(clientName)) {
            throw new RuntimeException("Client already connected: " + clientName);
        }

        var queue = new LinkedBlockingQueue<Packet>();
        queueMap.put(clientName, queue);
        return queue;
    }

    BlockingQueue<Packet> connectManInTheMiddle(String clientName) {
        if (manInTheMiddleName != null) {
            throw new RuntimeException("Man in the middle already connected: " + clientName);
        }
        manInTheMiddleName = clientName;
        manInTheMiddleQueue = new LinkedBlockingQueue<>();

        return manInTheMiddleQueue;
    }

    boolean send(Packet packet) {
        if (manInTheMiddleName != null) {
            return manInTheMiddleQueue.offer(packet);
        } else {
            return forward(packet);
        }
    }

    boolean forward(Packet packet) {
        if (queueMap.containsKey(packet.getDestination())) {
            return queueMap.get(packet.getDestination()).offer(packet);
        }
        throw new RuntimeException("Destination does not exist: " + packet.getDestination());
    }
}
