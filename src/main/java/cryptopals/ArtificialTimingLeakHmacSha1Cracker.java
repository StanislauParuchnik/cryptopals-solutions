package cryptopals;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HexFormat;
import java.util.function.UnaryOperator;

@Slf4j
@RequiredArgsConstructor
public class ArtificialTimingLeakHmacSha1Cracker {

    private static final int HMAC_SHA1_LENGTH = 20;
    private final UnaryOperator<Integer> numExecutionsResolver;
    private final int warmUpNumExecutions;

    public byte[] crack(int port, String file) throws IOException, InterruptedException {
        return crack(port, file, new byte[HMAC_SHA1_LENGTH], 0);
    }

    public byte[] crack(int port, String file,
                        byte[] startSignature, int startIdx) throws IOException, InterruptedException {
        if (startSignature.length != HMAC_SHA1_LENGTH) {
            throw new IllegalArgumentException("`start` length must be " + HMAC_SHA1_LENGTH);
        }

        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();


        var url = "http://localhost:" + port + "/test?file=" + file + "&signature=";
        var requestBuilder = HttpRequest.newBuilder().GET();

        var signature = new byte[HMAC_SHA1_LENGTH];
        System.arraycopy(startSignature, 0, signature, 0, startIdx);

        //warm up server
        var warmUpRequest = requestBuilder
                .uri(URI.create(url + HexFormat.of().formatHex(signature)))
                .build();
        for (int warmUp = 0; warmUp < warmUpNumExecutions; ++warmUp) {
            var response = client.send(warmUpRequest, HttpResponse.BodyHandlers.ofString());
            log.info("warm up {}", warmUp);
        }


        for (int i = startIdx; i < HMAC_SHA1_LENGTH; ++i) {
            log.info("Checking byte {} of signature", i);
            long maxExecutionTime = 0;
            byte maxExecutionTimeByte = 0;
            for (int b = 0; b < 256; ++b) {
                signature[i] = (byte) b;

                var request = requestBuilder
                        .uri(URI.create(url + HexFormat.of().formatHex(signature)))
                        .build();

                long totalExecutionTime = 0;
                int numExecutions = numExecutionsResolver.apply(i);
                for (int attempt = 0; attempt < numExecutions; ++attempt) {
                    var start = System.nanoTime();
                    var response = client.send(request, HttpResponse.BodyHandlers.ofString());
                    var end = System.nanoTime();

                    if (response.statusCode() == 200) {
                        return signature;
                    }

                    if (response.statusCode() != 500) {
                        throw new RuntimeException("Unknown status code");
                    }

                    totalExecutionTime += end - start;
                }

                //won't divide by numExecutions to get actual average

                if (totalExecutionTime > maxExecutionTime) {
                    maxExecutionTime = totalExecutionTime;
                    maxExecutionTimeByte = (byte) b;
                }

                signature[i] = maxExecutionTimeByte;
                log.info("b={} ({}): {} / {} ns | current best signature: {}",
                        b,
                        Integer.toHexString(0xff & b),
                        totalExecutionTime,
                        numExecutions,
                        HexFormat.of().formatHex(signature));
            }
            signature[i] = maxExecutionTimeByte;
            log.info("byte {} of signature is {}", i, Integer.toHexString(0xff & signature[i]));
        }

        log.info(HexFormat.of().formatHex(signature));
        return null;
    }
}
