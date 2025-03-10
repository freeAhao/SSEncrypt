package burp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.json.JSONObject;
import java.io.IOException;
import java.io.OutputStream;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class HttpHandlers {
    static class SSEHandler implements HttpHandler {
        private final BurpSSEPlugin plugin;

        public SSEHandler(BurpSSEPlugin plugin) {
            this.plugin = plugin;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            HttpUtils.setCORSHeaders(exchange);
            exchange.getResponseHeaders().set("Content-Type", "text/event-stream");
            exchange.getResponseHeaders().set("Cache-Control", "no-cache");
            exchange.getResponseHeaders().set("Connection", "keep-alive");
            exchange.sendResponseHeaders(200, 0);

            try (OutputStream os = exchange.getResponseBody()) {
                while (true) {
                    String msg = plugin.getMessages().take();
                    os.write(("data: " + msg + "\n\n").getBytes());
                    os.flush();
                }
            } catch (InterruptedException e) {
                plugin.getCallbacks().printOutput("SSE interrupted: " + e.getMessage());
            }
        }
    }

    static class ResultHandler implements HttpHandler {
        private final BurpSSEPlugin plugin;

        public ResultHandler(BurpSSEPlugin plugin) {
            this.plugin = plugin;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            HttpUtils.setCORSHeaders(exchange);
            if (!"POST".equals(exchange.getRequestMethod())) {
                HttpUtils.sendResponse(exchange, 405, "{\"error\": true, \"message\": \"Method not allowed\"}");
                return;
            }

            String requestBody = new String(exchange.getRequestBody().readAllBytes());
            try {
                JSONObject json = new JSONObject(requestBody);
                String taskId = json.getString("id");
                String output = json.getString("output");
                plugin.getResults().put(taskId, output);
                CountDownLatch latch = plugin.getResultEvents().get(taskId);
                if (latch != null) latch.countDown();
                HttpUtils.sendResponse(exchange, 200, "{\"error\": false}");
            } catch (Exception e) {
                plugin.getCallbacks().printError("Error in /result: " + e.getMessage());
                HttpUtils.sendResponse(exchange, 200, "{\"error\": true}");
            }
        }
    }

    static class InputHandler implements HttpHandler {
        private final BurpSSEPlugin plugin;

        public InputHandler(BurpSSEPlugin plugin) {
            this.plugin = plugin;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            HttpUtils.setCORSHeaders(exchange);
            if (!"POST".equals(exchange.getRequestMethod())) {
                HttpUtils.sendResponse(exchange, 405, "{\"error\": true, \"message\": \"Method not allowed\"}");
                return;
            }

            String requestBody = new String(exchange.getRequestBody().readAllBytes());
            try {
                JSONObject json = new JSONObject(requestBody);
                String taskId = UUID.randomUUID().toString();
                json.put("id", taskId);
                
                if (!json.has("script") && json.has("funcType") && json.has("funcName")) {
                    String script = "this.result(msg, msg.input);";
                    if (json.get("funcType").equals("enc") && plugin.encryptScripts.keySet().contains(json.getString("funcName"))){
                        script = plugin.encryptScripts.get(json.getString("funcName"));
                    } else if (json.get("funcType").equals("dec") && plugin.decryptScripts.keySet().contains(json.getString("funcName"))) {
                        script = plugin.decryptScripts.get(json.getString("funcName"));
                    }
                    json.put("script", script);
                }

                CountDownLatch latch = new CountDownLatch(1);
                plugin.getResultEvents().put(taskId, latch);
                plugin.getMessages().put(json.toString());

                boolean completed = latch.await(10, TimeUnit.SECONDS);
                String output = completed ? plugin.getResults().remove(taskId) : "Timeout";
                json.put("output", output != null ? output : "Timeout");
                json.put("error", !completed);
                plugin.getResultEvents().remove(taskId);

                HttpUtils.sendResponse(exchange, 200, json.toString());
            } catch (Exception e) {
                plugin.getCallbacks().printError("Error in /input: " + e.getMessage());
                HttpUtils.sendResponse(exchange, 200, "{\"error\": true, \"output\": \"Error\"}");
            }
        }
    }
}