package cryptopals.dh;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class MitmClient extends Client {

    private final Map<ProtocolHeader, ProtocolHandler<MitmClient>> mitmProtocolHandlers = new HashMap<>();

    @Getter
    private final Map<String, Map<String, BigInteger>> mitmDhKeyMap = new HashMap<>();

    public MitmClient(String name) {
        super(name);
    }

    private MitmClientWireConnection connection;

    public void sendAs(ProtocolHeader protocol, String source, String destination, byte[] message) {
        connection.writeAs(protocol, source, destination, message);
    }

    public void forward(Packet packet) {
        connection.forward(packet);
    }

    public void setConnection(MitmClientWireConnection connection) {
        super.setConnection(connection);
        this.connection = connection;
    }

    public void addMitmProtocolHandler(ProtocolHandler<MitmClient> handler) {
        mitmProtocolHandlers.put(handler.getSupportedHeader(), handler);
    }

    @Override
    protected void processPacket(Packet packet) throws Exception {
        if (mitmProtocolHandlers.containsKey(packet.getHeader())) {
            var handler = mitmProtocolHandlers.get(packet.getHeader());
            handler.handle(this, packet);
        } else if (protocolHandlers.containsKey(packet.getHeader())) {
            var handler = protocolHandlers.get(packet.getHeader());
            handler.handle(this, packet);
        } else {
            //just forward by default
            log.info("Received packet {}", packet);
            forward(packet);
        }
    }

    public void putMiTMDhKey(String initiator, String receiver,
                             BigInteger initiatorToReceiverKey,
                             BigInteger receiverToInitiatorKey) {
        mitmDhKeyMap.computeIfAbsent(initiator, k -> new HashMap<>());
        mitmDhKeyMap.computeIfAbsent(receiver, k -> new HashMap<>());

        mitmDhKeyMap.get(initiator).put(receiver, initiatorToReceiverKey);
        mitmDhKeyMap.get(receiver).put(initiator, receiverToInitiatorKey);
    }
}
