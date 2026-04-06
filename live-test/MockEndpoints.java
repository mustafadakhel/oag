import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public class MockEndpoints {
    public static void main(String[] args) throws Exception {
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 19100), 0);

        server.createContext("/classify", exchange -> {
            var body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8).toLowerCase();
            String response;
            if (body.contains("kill") || body.contains("attack") || body.contains("weapon") || body.contains("bomb")) {
                response = "{\"topic\":\"violence\",\"confidence\":0.95}";
            } else if (body.contains("money") || body.contains("invest") || body.contains("stock")) {
                response = "{\"topic\":\"finance\",\"confidence\":0.88}";
            } else if (body.contains("hack") || body.contains("exploit") || body.contains("breach")) {
                response = "{\"topic\":\"illegal_activity\",\"confidence\":0.91}";
            } else {
                response = "{\"topic\":\"general\",\"confidence\":0.70}";
            }
            try { send(exchange, response); } catch (Exception e) { e.printStackTrace(); }
        });

        server.createContext("/judge", exchange -> {
            var body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8).toLowerCase();
            double score = 0.1;
            String decision = "allow";
            String reason = "clean content";
            if (body.contains("ignore") && body.contains("instruction")) {
                score = 0.85; decision = "deny"; reason = "instruction override detected";
            } else if (body.contains("system prompt") || body.contains("reveal")) {
                score = 0.75; decision = "deny"; reason = "prompt extraction attempt";
            } else if (body.contains("dan") || body.contains("unrestricted")) {
                score = 0.92; decision = "deny"; reason = "jailbreak attempt";
            }
            var response = String.format("{\"score\":%.2f,\"decision\":\"%s\",\"reason\":\"%s\"}", score, decision, reason);
            try { send(exchange, response); } catch (Exception e) { e.printStackTrace(); }
        });

        server.start();
        System.out.println("Mock endpoints running on :19100 (/classify and /judge)");
        Thread.currentThread().join();
    }

    static void send(HttpExchange exchange, String body) throws Exception {
        var bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}
