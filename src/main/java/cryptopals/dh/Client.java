package cryptopals.dh;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;

@RequiredArgsConstructor
@Slf4j
public class Client {

    @Getter
    private final String name;

    @Setter
    private ClientWireConnection connection;

    protected final BlockingQueue<Command> commandsQueue = new LinkedBlockingQueue<>();
    protected final Map<ProtocolHeader, ProtocolHandler<Client>> protocolHandlers = new HashMap<>();

    private Thread handler = null;


    @Getter
    protected final Map<String, BigInteger> dhKeyMap = new HashMap<>();

    @Getter
    protected final Map<String, SrpPasswordVerifierParams> srpPasswordVerifier = new HashMap<>();

    private final ConcurrentMap<String, BlockingQueue<Object>> dataMap = new ConcurrentHashMap<>();

    public void send(ProtocolHeader protocol, String destination, byte[] message) {
        connection.write(protocol, destination, message);
    }

    public Packet read() throws InterruptedException {
        return connection.read();
    }

    public void addProtocolHandler(ProtocolHandler<Client> handler) {
        protocolHandlers.put(handler.getSupportedHeader(), handler);
    }

    public boolean runCommand(Command command) {
        return commandsQueue.offer(command);
    }

    public void start() {
        if (connection == null) {
            throw new RuntimeException("Client not connected");
        }
        if (handler != null) {
            throw new RuntimeException("Client already started");
        }

        handler = createHandlerThread();
        handler.start();
    }

    private Thread createHandlerThread() {
        return new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {

                    var packet = connection.tryRead();
                    if (packet != null) {
                        processPacket(packet);
                    }

                    var command = commandsQueue.poll(100, TimeUnit.MILLISECONDS);
                    if (command != null) {
                        command.runCommand(this);
                    }
                } catch (InterruptedException e) {
                    log.info("Thread interrupted");
                    return;
                } catch (Exception e) {
                    log.warn("Exception occurred", e);
                }
            }
            log.info("Thread interrupted");
        }, this.name);
    }

    protected void processPacket(Packet packet) throws Exception {
        var handler = protocolHandlers.get(packet.getHeader());
        handler.handle(this, packet);
    }

    public void stop() {
        if (handler == null) {
            throw new RuntimeException("Client not started");
        }
        handler.interrupt();
        handler = null;
    }

    //workaround to fetch data in tests
    public void publish(String key, Object value) {
        dataMap.compute(key, (a, b) -> b == null ? new LinkedBlockingQueue<>() : b).add(value);
    }

    public Object subscribe(String key, long timeoutMillis) throws InterruptedException {
        return dataMap.computeIfAbsent(key, k -> new LinkedBlockingQueue<>()).poll(timeoutMillis, TimeUnit.MILLISECONDS);
    }
}
