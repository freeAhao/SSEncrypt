package burp; /**
 * @author ahao
 * @date 2025/03/08
 */
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.json.JSONObject;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.logging.Logger;

public class BurpSSEPlugin implements IBurpExtender {
    private IBurpExtenderCallbacks callbacks;
    private HttpServer server;
    private JPanel panel;
    private JTextField portField;
    private JButton startButton;
    private JButton stopButton;
    private BlockingQueue<String> messages = new LinkedBlockingQueue<>(100);
    private ConcurrentHashMap<String, String> results = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, CountDownLatch> resultEvents = new ConcurrentHashMap<>();
    private volatile boolean isRunning = false;
    private BurpSSEPlugin burpExtender;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.burpExtender = this;
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        System.setOut(new PrintStream(callbacks.getStdout(),true));
        System.setErr(new PrintStream(callbacks.getStderr(),true));
        callbacks.setExtensionName("SSE Server Plugin");
        setupGUI();
    }

    private void setupGUI() {
        panel = new JPanel(new GridLayout(3, 2));
        portField = new JTextField("8081", 5);
        startButton = new JButton("Start Server");
        stopButton = new JButton("Stop Server");
        stopButton.setEnabled(false);

        panel.add(new JLabel("Port:"));
        panel.add(portField);
        panel.add(startButton);
        panel.add(stopButton);

        startButton.addActionListener(e -> startServer());
        stopButton.addActionListener(e -> stopServer());

        SwingUtilities.invokeLater(() -> callbacks.customizeUiComponent(panel));
        callbacks.addSuiteTab(new BurpTab());
    }

    private void startServer() {
        if (isRunning) return;
        try {
            int port = Integer.parseInt(portField.getText().trim());
            server = HttpServer.create(new InetSocketAddress(port), 0);

            // SSE端点
            server.createContext("/sse", new SSEHandler() {
                @Override
                public void handle(HttpExchange exchange) throws IOException {
                    setCORSHeaders(exchange);
                    super.handle(exchange);
                }
            });

            // Result端点
            server.createContext("/result", new ResultHandler() {
                @Override
                public void handle(HttpExchange exchange) throws IOException {
                    setCORSHeaders(exchange);
                    super.handle(exchange);
                }
            });

            // Input端点
            server.createContext("/input", new InputHandler() {
                @Override
                public void handle(HttpExchange exchange) throws IOException {
                    setCORSHeaders(exchange);
                    super.handle(exchange);
                }
            });

            server.setExecutor(Executors.newCachedThreadPool());
            server.start();
            isRunning = true;
            startButton.setEnabled(false);
            stopButton.setEnabled(true);
            callbacks.printOutput("Server started on port " + port);
        } catch (Exception e) {
            callbacks.printError("Error starting server: " + e.getMessage());
        }
    }

    // 添加CORS头的方法
    private void setCORSHeaders(HttpExchange exchange) {
        Headers headers = exchange.getResponseHeaders();
        headers.add("Access-Control-Allow-Origin", "*"); // 允许所有域名访问
        headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); // 允许的HTTP方法
        headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization"); // 允许的请求头
        headers.add("Access-Control-Max-Age", "86400"); // 预检请求缓存时间(秒)

        // 处理OPTIONS预检请求
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            try {
                exchange.sendResponseHeaders(204, -1); // No Content
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void stopServer() {
        if (!isRunning || server == null) return;
        server.stop(0);
        isRunning = false;
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        callbacks.printOutput("Server stopped");
    }

    class SSEHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "text/event-stream");
            exchange.getResponseHeaders().set("Cache-Control", "no-cache");
            exchange.getResponseHeaders().set("Connection", "keep-alive");
            exchange.sendResponseHeaders(200, 0);
            OutputStream os = exchange.getResponseBody();
            try {
                while (true) {
                    String msg = messages.take(); // Blocks until a message is available
                    os.write(("data: " + msg + "\n\n").getBytes());
                    os.flush();
                }
            } catch (InterruptedException e) {
                System.out.println("SSE interrupted: " + e.getMessage());
            } finally {
                os.close();
            }
        }
    }

    class ResultHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "{\"error\": true, \"message\": \"Method not allowed\"}");
                return;
            }
            String requestBody = new String(exchange.getRequestBody().readAllBytes());
            try {
                JSONObject json = new JSONObject(requestBody);
                String taskId = json.getString("id");
                String output = json.getString("output");
                results.put(taskId, output);
                CountDownLatch latch = resultEvents.get(taskId);
                if (latch != null) latch.countDown();
                sendResponse(exchange, 200, "{\"error\": false}");
            } catch (Exception e) {
                System.err.println("Error in /result: " + e.getMessage());
                sendResponse(exchange, 200, "{\"error\": true}");
            }
        }
    }

    class InputHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "{\"error\": true, \"message\": \"Method not allowed\"}");
                return;
            }
            String requestBody = new String(exchange.getRequestBody().readAllBytes());
            try {
                JSONObject json = new JSONObject(requestBody);
                String taskId = UUID.randomUUID().toString();
                String input = json.optString("input", "");
                int timeout = json.optInt("timeout", 10);

                json.put("id", taskId);
                json.put("input", input);

                CountDownLatch latch = new CountDownLatch(1);
                resultEvents.put(taskId, latch);
                messages.put(json.toString());

                boolean completed = latch.await(timeout, TimeUnit.SECONDS);
                String output = completed ? results.remove(taskId) : "Timeout";
                json.put("output", output != null ? output : "Timeout");
                json.put("error", !completed);
                resultEvents.remove(taskId);

                sendResponse(exchange, 200, json.toString());
            } catch (Exception e) {
                System.err.println("Error in /input: " + e.getMessage());
                sendResponse(exchange, 200, "{\"error\": true, \"output\": \"Error\"}");
            }
        }
    }

    private void sendResponse(HttpExchange exchange, int status, String response) throws IOException {
        exchange.sendResponseHeaders(status, response.length());
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response.getBytes());
        }
    }

    class BurpTab implements burp.ITab {
        @Override
        public String getTabCaption() {
            return "SSE Server";
        }

        @Override
        public Component getUiComponent() {
            return panel;
        }
    }


}