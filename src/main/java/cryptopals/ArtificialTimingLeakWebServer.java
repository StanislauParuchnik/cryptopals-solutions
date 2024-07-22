package cryptopals;

import ch.qos.logback.core.util.StringUtil;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

@Slf4j
public class ArtificialTimingLeakWebServer {

    private static final String FILE_PARAM = "file";
    private static final String SIGNATURE_PARAM = "signature";

    private final int port;
    private final long compareTimeoutMillis;
    private final HttpServer server;
    private final byte[] key;

    public ArtificialTimingLeakWebServer(int port, long compareTimeoutMillis) throws IOException {
        this.port = port;
        this.compareTimeoutMillis = compareTimeoutMillis;
        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/test", new MyHandler());
        server.setExecutor(null); // creates a default executor

        this.key = "What a beautiful day".getBytes(StandardCharsets.UTF_8);
    }

    public void start() {
        server.start();
    }

    public void stop() {
        server.stop(0);
    }

    class MyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            try {
                var params = parseQueryString(t.getRequestURI().getQuery());
                var fileName = params.get(FILE_PARAM);
                if (StringUtil.isNullOrEmpty(fileName)) {
                    throw new IllegalArgumentException("Missing file name");
                }
                var signature = params.get(SIGNATURE_PARAM);
                if (StringUtil.isNullOrEmpty(signature)) {
                    throw new IllegalArgumentException("Missing signature");
                }
                if (signature.length() != 40) {
                    throw new IllegalArgumentException("Invalid signature length");
                }
                var signatureBytes = HexFormat.of().parseHex(signature);

                var fileBytes = Files.readAllBytes(Paths.get("src\\main\\resources\\set4\\" + fileName));
                var correctHmac = hmacSha1(fileBytes);
//                log.info(HexFormat.of().formatHex(correctHmac));

                String response;
                if (insecureCompare(correctHmac, signatureBytes)) {
                    response = "Signature OK!";
                    t.sendResponseHeaders(200, 0);
                } else {
                    t.sendResponseHeaders(500, 0);
                    response = "Signature Invalid!";
                }

                OutputStream os = t.getResponseBody();
                os.write(response.getBytes());
                os.close();
            } catch (Exception e) {
                var response = "Error: " + e.getMessage();
                t.sendResponseHeaders(500, 0);
                OutputStream os = t.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }

        }
    }


    private static Map<String, String> parseQueryString(String qs) {
        Map<String, String> result = new HashMap<>();
        if (qs == null)
            return result;

        int last = 0, next, l = qs.length();
        while (last < l) {
            next = qs.indexOf('&', last);
            if (next == -1)
                next = l;

            if (next > last) {
                int eqPos = qs.indexOf('=', last);
                try {
                    if (eqPos < 0 || eqPos > next)
                        result.put(URLDecoder.decode(qs.substring(last, next), "utf-8"), "");
                    else
                        result.put(URLDecoder.decode(qs.substring(last, eqPos), "utf-8"), URLDecoder.decode(qs.substring(eqPos + 1, next), "utf-8"));
                } catch (UnsupportedEncodingException e) {
                    throw new RuntimeException(e); // will never happen, utf-8 support is mandatory for java
                }
            }
            last = next + 1;
        }
        return result;
    }

    private boolean insecureCompare(byte[] b1, byte[] b2) throws InterruptedException {
        if (b1 == null) {
            return b2 == null;
        }
        if (b2 == null) {
            return false;
        }
        if (b1.length != b2.length) {
            return false;
        }

        for (int i = 0; i < b1.length; i++) {
            if (b1[i] != b2[i]) {
                return false;
            }
            //add artificial timing leak
            if (compareTimeoutMillis > 0) {
                Thread.sleep(compareTimeoutMillis);
            }
        }

        return true;
    }

    private byte[] hmacSha1(byte[] input) {
        try {
            // Get an hmac_sha1 key from the raw key bytes
            SecretKeySpec signingKey = new SecretKeySpec(key, "HmacSHA1");

            // Get an hmac_sha1 Mac instance and initialize with the signing key
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(signingKey);

            // Compute the hmac on input data bytes

            return mac.doFinal(input);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
