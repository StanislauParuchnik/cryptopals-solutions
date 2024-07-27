package cryptopals.dh;

import cryptopals.Utils;
import cryptopals.ciphers.Aes128CbcPkcs7Cipher;
import cryptopals.hash.SHA1;
import lombok.extern.slf4j.Slf4j;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

@Slf4j
public class DiffieHellman {

    public static Command initiateDHNegotiatedGroupCommand(String target, BigInteger p, BigInteger g) {
        return initiator -> {
            var a = Utils.randomBigInteger(p);
            log.debug("Generated a");

            //Generate "a", a random number mod 37. Now generate "A", which is "g" raised to the "a" power mode 37 --- A = (g**a) % p.
            var gA = g.modPow(a, p);
            log.debug("Calculated gA");

            initiator.send(ProtocolHeader.DIFFIE_HELLMAN, target, p.toByteArray());
            log.debug("Sent p to {}", target);
            initiator.send(ProtocolHeader.DIFFIE_HELLMAN, target, g.toByteArray());
            log.debug("Sent g to {}", target);

            var packet = initiator.read();
            validateSource(packet, target);
            if (packet.getData().length != 1 && packet.getData()[0] != 1) {
                log.debug("ACK not received from {}", target);
                throw new RuntimeException("ACK not received from " + target);
            }

            initiator.send(ProtocolHeader.DIFFIE_HELLMAN, target, gA.toByteArray());
            log.debug("Sent gA to {}", target);


            packet = initiator.read();
            validateSource(packet, target);

            var gB = new BigInteger(packet.getData());
            log.debug("Received gB from {}", target);

            var sharedKey = gB.modPow(a, p);
            log.debug("Generated shared key {} <-> {}: {}", initiator.getName(), target, sharedKey);

            initiator.getDhKeyMap().put(target, sharedKey);
            initiator.publish(ProtocolHeader.DIFFIE_HELLMAN.name(), target);
        };
    }

    public static ProtocolHandler<Client> dhNegotiatedGroupProtocolHandler() {
        return new ProtocolHandler<>() {
            @Override
            public void handle(Client receiver, Packet packet) throws Exception {
                var initiator = packet.getSource();
                var p = new BigInteger(packet.getData());
                log.debug("Received p from {}", initiator);

                packet = receiver.read();
                validateSource(packet, initiator);
                var g = new BigInteger(packet.getData());
                log.debug("Received g from {}", initiator);

                receiver.send(ProtocolHeader.DIFFIE_HELLMAN, initiator, new byte[]{1});
                log.debug("Sent ACK to {}", initiator);

                packet = receiver.read();
                validateSource(packet, initiator);

                var gA = new BigInteger(packet.getData());
                log.debug("Received gA from {}", initiator);


                var b = Utils.randomBigInteger(p);
                log.debug("Generated b");

                var gB = g.modPow(b, p);
                log.debug("Sent gB to {}", initiator);

                receiver.send(ProtocolHeader.DIFFIE_HELLMAN, initiator, gB.toByteArray());

                var sharedKey = gA.modPow(b, p);
                log.debug("Generated shared key {} <-> {}: {}", initiator, receiver.getName(), sharedKey);

                receiver.getDhKeyMap().put(initiator, sharedKey);
                receiver.publish(ProtocolHeader.DIFFIE_HELLMAN.name(), initiator);
            }

            @Override
            public ProtocolHeader getSupportedHeader() {
                return ProtocolHeader.DIFFIE_HELLMAN;
            }
        };
    }

    private static void validateSource(Packet packet, String source) {
        if (!source.equals(packet.getSource())) {
            throw new RuntimeException("Invalid source: " + source);
        }
    }

    private static void validateDestination(Packet packet, String destination) {
        if (!destination.equals(packet.getDestination())) {
            throw new RuntimeException("Invalid destination: " + destination);
        }
    }

    public static ProtocolHandler<MitmClient> mitmKeyFixingDHProtocolHandler() {
        return new ProtocolHandler<>() {
            @Override
            public void handle(MitmClient mitmClient, Packet packet) throws Exception {
                var initiator = packet.getSource();
                var receiver = packet.getDestination();

                var p = new BigInteger(packet.getData());
                log.debug("Received p from {}", initiator);
                mitmClient.forward(packet);
                log.debug("Relayed p to {}", receiver);


                packet = mitmClient.read();
                //of course in reality man in the middle doesn't throw :)
                validateSource(packet, initiator);
                validateDestination(packet, receiver);
                log.debug("Received g from {}", initiator);
                mitmClient.forward(packet);
                log.debug("Relayed g to {}", receiver);

                packet = mitmClient.read();
                validateSource(packet, receiver);
                validateDestination(packet, initiator);
                if (packet.getData().length != 1 && packet.getData()[0] != 1) {
                    log.info("ACK not received from {}", receiver);
                    return;
                }
                mitmClient.forward(packet);
                log.debug("Relayed ACK to {}", initiator);


                packet = mitmClient.read();
                validateSource(packet, initiator);
                validateDestination(packet, receiver);
                log.debug("Received gA from {}", initiator);
                mitmClient.sendAs(ProtocolHeader.DIFFIE_HELLMAN, initiator, receiver, p.toByteArray());
                log.debug("Replaced gA with p and sent to {}", receiver);

                packet = mitmClient.read();
                validateSource(packet, receiver);
                validateDestination(packet, initiator);
                log.debug("Received gB from {}", receiver);
                mitmClient.sendAs(ProtocolHeader.DIFFIE_HELLMAN, receiver, initiator, p.toByteArray());
                log.debug("Replaced gB with p and sent to {}", initiator);

                //now key should be 0 for both parties
                mitmClient.putMiTMDhKey(initiator, receiver, BigInteger.ZERO, BigInteger.ZERO);
            }

            @Override
            public ProtocolHeader getSupportedHeader() {
                return ProtocolHeader.DIFFIE_HELLMAN;
            }
        };
    }

    public static ProtocolHandler<MitmClient> mitmClassicDHProtocolHandler() {
        return new ProtocolHandler<>() {
            @Override
            public void handle(MitmClient mitmClient, Packet packet) throws Exception {
                var initiator = packet.getSource();
                var receiver = packet.getDestination();

                var p = new BigInteger(packet.getData());
                log.debug("Received p from {}", initiator);
                mitmClient.forward(packet);
                log.debug("Relayed p to {}", receiver);


                packet = mitmClient.read();
                //of course in reality man in the middle doesn't throw :)
                validateSource(packet, initiator);
                validateDestination(packet, receiver);
                var g = new BigInteger(packet.getData());
                log.debug("Received g from {}", initiator);
                mitmClient.forward(packet);
                log.debug("Relayed g to {}", receiver);

                packet = mitmClient.read();
                validateSource(packet, receiver);
                validateDestination(packet, initiator);
                if (packet.getData().length != 1 && packet.getData()[0] != 1) {
                    log.info("ACK not received from {}", receiver);
                    return;
                }
                mitmClient.forward(packet);
                log.debug("Relayed ACK to {}", initiator);


                packet = mitmClient.read();
                validateSource(packet, initiator);
                validateDestination(packet, receiver);
                var gA = new BigInteger(packet.getData());
                log.debug("Received gA from {}", initiator);

                var ma = Utils.randomBigInteger(p);
                var mA = g.modPow(ma, p);
                mitmClient.sendAs(ProtocolHeader.DIFFIE_HELLMAN, initiator, receiver, mA.toByteArray());
                log.debug("Replaced gA with mA and sent to {}", receiver);

                packet = mitmClient.read();
                validateSource(packet, receiver);
                validateDestination(packet, initiator);
                var gB = new BigInteger(packet.getData());
                log.debug("Received gB from {}", receiver);

                var mb = Utils.randomBigInteger(p);
                var mB = g.modPow(mb, p);
                mitmClient.sendAs(ProtocolHeader.DIFFIE_HELLMAN, receiver, initiator, mB.toByteArray());
                log.debug("Replaced gB with mB and sent to {}", initiator);

                //generate keys
                var initiatorToReceiverKey = gA.modPow(mb, p);
                log.debug("Generated shared key {} <-> {} ({}): {}", initiator, mitmClient.getName(), receiver, initiatorToReceiverKey);
                var receiverToInitiatorKey = gB.modPow(ma, p);
                log.debug("Generated shared key {} <-> {} ({}): {}", receiver, mitmClient.getName(), initiator, receiverToInitiatorKey);

                mitmClient.putMiTMDhKey(initiator, receiver, initiatorToReceiverKey, receiverToInitiatorKey);
            }

            @Override
            public ProtocolHeader getSupportedHeader() {
                return ProtocolHeader.DIFFIE_HELLMAN;
            }
        };
    }

    public static Command sendEncryptedMessage(String target, String message) {
        return client -> {
            var key = Arrays.copyOf(
                    new SHA1().digest(client.getDhKeyMap().get(target).toByteArray()),
                    Utils.AES_128_BLOCK_SIZE_IN_BYTES
            );
            var iv = Utils.randomBytes(Utils.AES_128_BLOCK_SIZE_IN_BYTES);
            var cipher = new Aes128CbcPkcs7Cipher();

            var encrypted = cipher.encrypt(message.getBytes(StandardCharsets.UTF_8), iv, key);

            client.send(ProtocolHeader.ENCRYPTED_MESSAGE, target, Utils.concat(iv, encrypted));
            log.debug("Sent encrypted message to {}", target);
        };
    }

    public static ProtocolHandler<Client> echoEncryptedMessage() {
        return new ProtocolHandler<>() {
            @Override
            public void handle(Client receiver, Packet packet) throws Exception {
                var source = packet.getSource();
                var encryptedMessageAndIv = packet.getData();

                var key = Arrays.copyOf(
                        new SHA1().digest(receiver.getDhKeyMap().get(source).toByteArray()),
                        Utils.AES_128_BLOCK_SIZE_IN_BYTES
                );

                var iv = Arrays.copyOfRange(encryptedMessageAndIv, 0, Utils.AES_128_BLOCK_SIZE_IN_BYTES);
                var encryptedMessage = Arrays.copyOfRange(encryptedMessageAndIv, Utils.AES_128_BLOCK_SIZE_IN_BYTES, encryptedMessageAndIv.length);

                var cipher = new Aes128CbcPkcs7Cipher();
                var decrypted = cipher.decrypt(encryptedMessage, iv, key);

                var decryptedStr = new String(decrypted);
                log.debug("Received Message from {}: {}", source, decryptedStr);

                //send message back
                iv = Utils.randomBytes(Utils.AES_128_BLOCK_SIZE_IN_BYTES);

                var encrypted = cipher.encrypt(decrypted, iv, key);

                var responseData = Utils.concat(iv, encrypted);

                receiver.send(ProtocolHeader.ENCRYPTED_MESSAGE, source, responseData);
                log.debug("Sent message back to {}", source);

                receiver.publish(ProtocolHeader.ENCRYPTED_MESSAGE.name(), decryptedStr);
            }

            @Override
            public ProtocolHeader getSupportedHeader() {
                return ProtocolHeader.ENCRYPTED_MESSAGE;
            }
        };
    }

    public static ProtocolHandler<Client> printEncryptedMessage() {
        return new ProtocolHandler<>() {
            @Override
            public void handle(Client receiver, Packet packet) throws Exception {
                var source = packet.getSource();
                var encryptedMessageAndIv = packet.getData();

                var key = Arrays.copyOf(
                        new SHA1().digest(receiver.getDhKeyMap().get(source).toByteArray()),
                        Utils.AES_128_BLOCK_SIZE_IN_BYTES
                );

                var iv = Arrays.copyOfRange(encryptedMessageAndIv, 0, Utils.AES_128_BLOCK_SIZE_IN_BYTES);
                var encryptedMessage = Arrays.copyOfRange(encryptedMessageAndIv, Utils.AES_128_BLOCK_SIZE_IN_BYTES, encryptedMessageAndIv.length);

                var cipher = new Aes128CbcPkcs7Cipher();
                var decrypted = cipher.decrypt(encryptedMessage, iv, key);

                var decryptedStr = new String(decrypted);
                log.debug("Received Message from {}: {}", source, decryptedStr);

                receiver.publish(ProtocolHeader.ENCRYPTED_MESSAGE.name(), decryptedStr);
            }

            @Override
            public ProtocolHeader getSupportedHeader() {
                return ProtocolHeader.ENCRYPTED_MESSAGE;
            }
        };
    }

    public static ProtocolHandler<MitmClient> mitmSniffEncryptedMessageHandler() {
        return new ProtocolHandler<>() {
            @Override
            public void handle(MitmClient mitmClient, Packet packet) throws Exception {
                log.debug("Received packet {}", packet);

                var source = packet.getSource();
                var destination = packet.getDestination();

                if (mitmClient.getMitmDhKeyMap().containsKey(source)) {
                    log.debug("Shared key found, decrypting message...");

                    var encryptedMessageAndIv = packet.getData();

                    var initiatorKey = mitmClient.getMitmDhKeyMap().get(source).get(destination);
                    var key = Arrays.copyOf(
                            new SHA1().digest(initiatorKey.toByteArray()),
                            Utils.AES_128_BLOCK_SIZE_IN_BYTES
                    );

                    var iv = Arrays.copyOfRange(encryptedMessageAndIv, 0, Utils.AES_128_BLOCK_SIZE_IN_BYTES);
                    var encryptedMessage = Arrays.copyOfRange(encryptedMessageAndIv, Utils.AES_128_BLOCK_SIZE_IN_BYTES, encryptedMessageAndIv.length);

                    var cipher = new Aes128CbcPkcs7Cipher();
                    var decrypted = cipher.decrypt(encryptedMessage, iv, key);

                    var decryptedStr = new String(decrypted);
                    log.debug("Decrypted message {} -> {}: {}", source, destination, decryptedStr);

                    var receiverKey = mitmClient.getMitmDhKeyMap().get(destination).get(source);

                    if (!initiatorKey.equals(receiverKey)) {
                        log.debug("Re-encrypt message for {}", destination);
                        key = Arrays.copyOf(
                                new SHA1().digest(receiverKey.toByteArray()),
                                Utils.AES_128_BLOCK_SIZE_IN_BYTES
                        );

                        //we can actually use the same iv from source
                        iv = Utils.randomBytes(Utils.AES_128_BLOCK_SIZE_IN_BYTES);

                        var reencryptedMessage = cipher.encrypt(decrypted, iv, key);

                        mitmClient.sendAs(ProtocolHeader.ENCRYPTED_MESSAGE, source, destination,
                                Utils.concat(iv, reencryptedMessage));

                    } else {
                        log.debug("initiator key and receiver keys are equal, no need to re-encrypt");
                        mitmClient.forward(packet);
                    }

                    mitmClient.publish(ProtocolHeader.ENCRYPTED_MESSAGE.name(), decryptedStr);
                } else {
                    log.debug("Shared key not found, relaying packet");
                    mitmClient.forward(packet);
                }
            }

            @Override
            public ProtocolHeader getSupportedHeader() {
                return ProtocolHeader.ENCRYPTED_MESSAGE;
            }
        };
    }

    public static ProtocolHandler<MitmClient> mitmDHMaliciousGProtocolHandler() {
        return new ProtocolHandler<>() {
            @Override
            public void handle(MitmClient mitmClient, Packet packet) throws Exception {
                var initiator = packet.getSource();
                var receiver = packet.getDestination();

                var p = new BigInteger(packet.getData());
                log.debug("Received p from {}", initiator);
                mitmClient.forward(packet);
                log.debug("Relayed p to {}", receiver);


                packet = mitmClient.read();
                //of course in reality man in the middle doesn't throw :)
                validateSource(packet, initiator);
                validateDestination(packet, receiver);
                var g = new BigInteger(packet.getData());
                log.debug("Received g from {}", initiator);
                mitmClient.forward(packet);
                log.debug("Relayed g to {}", receiver);

                packet = mitmClient.read();
                validateSource(packet, receiver);
                validateDestination(packet, initiator);
                if (packet.getData().length != 1 && packet.getData()[0] != 1) {
                    log.info("ACK not received from {}", receiver);
                    return;
                }
                mitmClient.forward(packet);
                log.debug("Relayed ACK to {}", initiator);


                packet = mitmClient.read();
                validateSource(packet, initiator);
                validateDestination(packet, receiver);
                var gA = new BigInteger(packet.getData());
                log.debug("Received gA from {}", initiator);
                mitmClient.forward(packet);
                log.debug("Relayed gA to {}", receiver);

                packet = mitmClient.read();
                validateSource(packet, receiver);
                validateDestination(packet, initiator);
                var gB = new BigInteger(packet.getData());
                log.debug("Received gB from {}", receiver);

                mitmClient.forward(packet);
                log.debug("Relayed gB to {}", initiator);


                BigInteger initiatorToReceiverKey;
                BigInteger receiverToInitiatorKey;

                BigInteger pMinus1 =p.subtract(BigInteger.ONE);
                if (g.equals(BigInteger.ONE)) {
                    log.debug("Detected malicious g = 1");
                    //key = 1 for both parties because gB = (1 ** b) mod p = 1
                    initiatorToReceiverKey = BigInteger.ONE;
                    receiverToInitiatorKey = BigInteger.ONE;
                } else if (g.equals(p)) {
                    log.debug("Detected malicious g = p");
                    //key = 0 for both parties because g = 0 mod p and 0 to any power is zero
                    initiatorToReceiverKey = BigInteger.ZERO;
                    receiverToInitiatorKey = BigInteger.ZERO;
                } else if (g.equals(pMinus1)) {
                    //g = p-1 mod p = (-1) mod p, so shared key is either 1 or p-1 depending on parity of a and b

                    boolean aIsEven = gA.equals(BigInteger.ONE);
                    boolean bIsEven = gB.equals(BigInteger.ONE);

                    if (aIsEven || bIsEven) {
                        //key = (-1) ** (a*b) mod p = (-1) ** (even power) pod p = 1
                        initiatorToReceiverKey = BigInteger.ONE;
                        receiverToInitiatorKey = BigInteger.ONE;
                    } else {
                        //key = (-1) ** (a*b) mod p = (-1) ** (odd power) pod p = (-1) mod p = p - 1
                        initiatorToReceiverKey = pMinus1;
                        receiverToInitiatorKey = pMinus1;
                    }
                } else {
                    log.info("Unknown malicious g param, won't generate keys");
                    return;
                }

                log.debug("Generated shared key {} <-> {} ({}): {}", initiator, mitmClient.getName(), receiver, initiatorToReceiverKey);
                log.debug("Generated shared key {} <-> {} ({}): {}", receiver, mitmClient.getName(), initiator, receiverToInitiatorKey);

                mitmClient.putMiTMDhKey(initiator, receiver, initiatorToReceiverKey, receiverToInitiatorKey);
            }

            @Override
            public ProtocolHeader getSupportedHeader() {
                return ProtocolHeader.DIFFIE_HELLMAN;
            }
        };
    }
}
