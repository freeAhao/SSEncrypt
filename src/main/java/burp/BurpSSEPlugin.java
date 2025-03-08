package burp; /**
 * @author ahao
 * @date 2025/03/08
 */
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
    private static final Logger logger = Logger.getLogger(BurpSSEPlugin.class.getName());
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
        this.stdout = new PrintWriter(callbacks.getStdout(),true);
        this.stderr = new PrintWriter(callbacks.getStderr(),true);
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
            server.createContext("/sse", new SSEHandler());
            server.createContext("/result", new ResultHandler());
            server.createContext("/input", new InputHandler());
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
                logger.warning("SSE interrupted: " + e.getMessage());
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
                logger.severe("Error in /result: " + e.getMessage());
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
                logger.severe("Error in /input: " + e.getMessage());
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