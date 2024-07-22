package cryptopals.dh;

import cryptopals.Utils;
import lombok.extern.slf4j.Slf4j;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

@Slf4j
public class DiffieHellman {

    private static final String DH_HEADER = "Let's do DH!";

    public static Thread DHInitiatorThread(Client initiator, String target, BigInteger p, BigInteger g) {
        return new Thread(() -> {
            try {
                log.info("Starting DH with {}", target);
                initiator.send(target, "Let's do DH!".getBytes(StandardCharsets.UTF_8));
                var packet = initiator.read();
                var message = new String(packet.getData(), StandardCharsets.UTF_8);

                if (DH_HEADER.equals(message)) {
                    log.info("Received DH header from {}", target);
                } else {
                    throw new RuntimeException("Unknown message: " + message);
                }

                //now both parties agree to do DH
                var a = Utils.randomBigInteger(p);
                log.debug("Generated a");

                //Generate "a", a random number mod 37. Now generate "A", which is "g" raised to the "a" power mode 37 --- A = (g**a) % p.
                var gA = g.modPow(a, p);
                log.debug("Calculated gA");

                initiator.send(target, gA.toByteArray());
                log.debug("Sent gA to {}", target);

                packet = initiator.read();
                validateSource(packet, target);

                var gB = new BigInteger(packet.getData());
                log.debug("Received gB from {}", target);

                var sharedKey = gB.modPow(a, p);
                log.info("Generated shared key {} <-> {}: {}", initiator.getName(), target, sharedKey);

                initiator.getDhKeyMap().put(target, sharedKey);

            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }, initiator.getName());
    }

    public static Thread DHReceiverThread(Client receiver, BigInteger p, BigInteger g) {
        return new Thread(() -> {
            try {
                var packet = receiver.read();
                var initiator = packet.getSource();
                var message = new String(packet.getData(), StandardCharsets.UTF_8);
                if (DH_HEADER.equals(message)) {
                    log.info("Received DH header from {}", initiator);
                    receiver.send(packet.getSource(), DH_HEADER.getBytes(StandardCharsets.UTF_8));
                } else {
                    throw new RuntimeException("Unknown message: " + message);
                }

                //now both parties agree to do DH

                var b = Utils.randomBigInteger(p);
                log.debug("Generated b");

                var gB = g.modPow(b, p);
                log.debug("Sent gB to {}", initiator);

                receiver.send(initiator, gB.toByteArray());

                packet = receiver.read();
                validateSource(packet, initiator);

                var gA = new BigInteger(packet.getData());
                log.debug("Received gA from {}", initiator);

                var sharedKey = gA.modPow(b, p);
                log.info("Generated shared key {} <-> {}: {}", initiator, receiver.getName(), sharedKey);

                receiver.getDhKeyMap().put(initiator, sharedKey);

            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }, receiver.getName());
    }

    private static void validateSource(Packet packet, String source) {
        if (!source.equals(packet.getSource())) {
            throw new RuntimeException("Invalid source: " + source);
        }
    }
}
