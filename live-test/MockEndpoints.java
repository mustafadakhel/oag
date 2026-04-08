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

        server.createContext("/mock-llm", exchange -> {
            var body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8).toLowerCase();
            String response;
            if (body.contains("hallucinate") || body.contains("impossible")) {
                // Response with impossible claims and low-confidence logprobs
                response = """
                    {
                      "id": "chatcmpl-mock-hallucination",
                      "object": "chat.completion",
                      "model": "gpt-4",
                      "choices": [{
                        "index": 0,
                        "message": {
                          "role": "assistant",
                          "content": "You should upgrade to Python 4.0 which was released in 2025. It includes native support for quantum computing via the built-in qbit module. Also, Java 26 introduced value types that replaced all primitive wrappers."
                        },
                        "finish_reason": "stop",
                        "logprobs": {
                          "content": [
                            {"token": "You", "logprob": -3.2},
                            {"token": " should", "logprob": -4.1},
                            {"token": " upgrade", "logprob": -5.5},
                            {"token": " to", "logprob": -3.8},
                            {"token": " Python", "logprob": -4.9},
                            {"token": " 4", "logprob": -6.2},
                            {"token": ".0", "logprob": -5.7}
                          ]
                        }
                      }],
                      "usage": {"prompt_tokens": 25, "completion_tokens": 40, "total_tokens": 65}
                    }""";
            } else if (body.contains("logprob")) {
                // Response with low-confidence logprobs only (no impossible claims)
                response = """
                    {
                      "id": "chatcmpl-mock-lowconf",
                      "object": "chat.completion",
                      "model": "gpt-4",
                      "choices": [{
                        "index": 0,
                        "message": {
                          "role": "assistant",
                          "content": "The framework uses a middleware pattern for request processing."
                        },
                        "finish_reason": "stop",
                        "logprobs": {
                          "content": [
                            {"token": "The", "logprob": -4.5},
                            {"token": " framework", "logprob": -5.8},
                            {"token": " uses", "logprob": -6.1},
                            {"token": " a", "logprob": -4.9},
                            {"token": " middleware", "logprob": -7.2}
                          ]
                        }
                      }],
                      "usage": {"prompt_tokens": 20, "completion_tokens": 12, "total_tokens": 32}
                    }""";
            } else {
                // Clean response with high-confidence logprobs
                response = """
                    {
                      "id": "chatcmpl-mock-clean",
                      "object": "chat.completion",
                      "model": "gpt-4",
                      "choices": [{
                        "index": 0,
                        "message": {
                          "role": "assistant",
                          "content": "Python 3.12 introduced several performance improvements including a specializing adaptive interpreter."
                        },
                        "finish_reason": "stop",
                        "logprobs": {
                          "content": [
                            {"token": "Python", "logprob": -0.3},
                            {"token": " 3", "logprob": -0.1},
                            {"token": ".12", "logprob": -0.2},
                            {"token": " introduced", "logprob": -0.4},
                            {"token": " several", "logprob": -0.5}
                          ]
                        }
                      }],
                      "usage": {"prompt_tokens": 15, "completion_tokens": 18, "total_tokens": 33}
                    }""";
            }
            try { send(exchange, response); } catch (Exception e) { e.printStackTrace(); }
        });

        server.start();
        System.out.println("Mock endpoints running on :19100 (/classify, /judge, and /mock-llm)");
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
