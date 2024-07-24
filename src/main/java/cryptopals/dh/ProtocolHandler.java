package cryptopals.dh;

public interface ProtocolHandler<T extends Client> {

    void handle(T client, Packet packet) throws Exception;

    ProtocolHeader getSupportedHeader();
}
