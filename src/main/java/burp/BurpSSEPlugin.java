package burp;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.json.JSONObject;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;

public class BurpSSEPlugin implements IBurpExtender, IContextMenuFactory, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private HttpServer server;
    private JPanel panel;
    private JTextField portField;
    private JButton startButton, stopButton;
    private JList<String> scriptList;
    private DefaultListModel<String> scriptListModel;
    private JTextField scriptNameField;
    private JTextArea scriptContentArea;
    private BlockingQueue<String> messages = new LinkedBlockingQueue<>(100);
    private ConcurrentHashMap<String, String> results = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, CountDownLatch> resultEvents = new ConcurrentHashMap<>();
    private volatile boolean isRunning = false;
    private Map<String, String> scripts = new HashMap<>(); // 存储脚本名称和内容

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("SSE Server Plugin");
        callbacks.registerContextMenuFactory(this);
        callbacks.registerHttpListener(this);
        setupGUI();
    }

    private void setupGUI() {
        panel = new JPanel(new BorderLayout());

        // 服务器控制面板
        JPanel serverPanel = new JPanel(new GridLayout(2, 2));
        portField = new JTextField("8081", 5);
        startButton = new JButton("Start Server");
        stopButton = new JButton("Stop Server");
        stopButton.setEnabled(false);
        serverPanel.add(new JLabel("Port:"));
        serverPanel.add(portField);
        serverPanel.add(startButton);
        serverPanel.add(stopButton);

        // 脚本管理面板
        JPanel scriptPanel = new JPanel(new BorderLayout());
        scriptListModel = new DefaultListModel<>();
        scriptList = new JList<>(scriptListModel);
        scriptNameField = new JTextField(20);
        scriptContentArea = new JTextArea(10, 30);

        JPanel scriptControlPanel = new JPanel();
        JButton addScript = new JButton("Add");
        JButton editScript = new JButton("Edit");
        JButton deleteScript = new JButton("Delete");

        scriptControlPanel.add(new JLabel("Script Name:"));
        scriptControlPanel.add(scriptNameField);
        scriptControlPanel.add(addScript);
        scriptControlPanel.add(editScript);
        scriptControlPanel.add(deleteScript);

        scriptPanel.add(new JScrollPane(scriptList), BorderLayout.WEST);
        scriptPanel.add(new JScrollPane(scriptContentArea), BorderLayout.CENTER);
        scriptPanel.add(scriptControlPanel, BorderLayout.NORTH);

        panel.add(serverPanel, BorderLayout.NORTH);
        panel.add(scriptPanel, BorderLayout.CENTER);

        // 事件监听
        startButton.addActionListener(e -> startServer());
        stopButton.addActionListener(e -> stopServer());

        addScript.addActionListener(e -> addScript());
        editScript.addActionListener(e -> editScript());
        deleteScript.addActionListener(e -> deleteScript());
        scriptList.addListSelectionListener(e -> {
            String selected = scriptList.getSelectedValue();
            if (selected != null) {
                scriptNameField.setText(selected);
                scriptContentArea.setText(scripts.get(selected));
            }
        });

        SwingUtilities.invokeLater(() -> callbacks.customizeUiComponent(panel));
        callbacks.addSuiteTab(new BurpTab());
    }

    private void addScript() {
        String name = scriptNameField.getText().trim();
        String content = scriptContentArea.getText().trim();
        if (!name.isEmpty() && !content.isEmpty()) {
            scripts.put(name, content);
            if (!scriptListModel.contains(name)) {
                scriptListModel.addElement(name);
            }
            callbacks.printOutput("Script added: " + name);
        }
    }

    private void editScript() {
        String selected = scriptList.getSelectedValue();
        if (selected != null) {
            String newName = scriptNameField.getText().trim();
            String content = scriptContentArea.getText().trim();
            if (!newName.isEmpty() && !content.isEmpty()) {
                scripts.remove(selected);
                scripts.put(newName, content);
                int index = scriptListModel.indexOf(selected);
                scriptListModel.set(index, newName);
                callbacks.printOutput("Script updated: " + newName);
            }
        }
    }

    private void deleteScript() {
        String selected = scriptList.getSelectedValue();
        if (selected != null) {
            scripts.remove(selected);
            scriptListModel.removeElement(selected);
            scriptNameField.setText("");
            scriptContentArea.setText("");
            callbacks.printOutput("Script deleted: " + selected);
        }
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
                    super.handle(exchange);
                }
            });

            // Result端点
            server.createContext("/result", new ResultHandler() {
                @Override
                public void handle(HttpExchange exchange) throws IOException {
                    super.handle(exchange);
                }
            });

            // Input端点
            server.createContext("/input", new InputHandler() {
                @Override
                public void handle(HttpExchange exchange) throws IOException {
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

    private void stopServer() {
        if (!isRunning || server == null) return;
        server.stop(0);
        isRunning = false;
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        callbacks.printOutput("Server stopped");
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
                invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
            List<JMenuItem> menu = new ArrayList<>();
            JMenu scriptMenu = new JMenu("Apply SSE Script");
            for (String scriptName : scripts.keySet()) {
                JMenuItem item = new JMenuItem(scriptName);
                item.addActionListener(e -> {
                    int[] bounds = invocation.getSelectionBounds();
                    IHttpRequestResponse message = invocation.getSelectedMessages()[0];
                    byte[] request = message.getRequest();
                    String selectedText = new String(Arrays.copyOfRange(request, bounds[0], bounds[1]));
                    String taggedText = String.format("[[%s:%s]]", scriptName, selectedText);
                    byte[] newRequest = helpers.stringToBytes(
                            new String(request, 0, bounds[0]) + taggedText + new String(request, bounds[1], request.length - bounds[1])
                    );
                    message.setRequest(newRequest);
                });
                scriptMenu.add(item);
            }
            menu.add(scriptMenu);
            return menu;
        }
        return null;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest || !(toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER || toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER)) {
            return;
        }

        try {
            byte[] request = messageInfo.getRequest();
            if (request == null) {
                callbacks.printError("Request is null");
                return;
            }

            // 使用 Burp 的 helpers 解析请求
            IRequestInfo requestInfo = helpers.analyzeRequest(request);
            String requestStr = helpers.bytesToString(request);
            callbacks.printOutput("Original request: " + requestStr);

            // 分离头部和 body
            int bodyOffset = requestInfo.getBodyOffset();
            String headersStr = requestStr.substring(0, bodyOffset);
            String bodyStr = requestStr.substring(bodyOffset);

            // 处理标签
            String regex = "\\[\\[(.+?):(.+?)\\]\\]";
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(regex);
            java.util.regex.Matcher matcher = pattern.matcher(bodyStr);

            StringBuilder modifiedBody = new StringBuilder();
            int lastEnd = 0;
            boolean bodyModified = false;

            while (matcher.find()) {
                modifiedBody.append(bodyStr.substring(lastEnd, matcher.start()));
                String scriptName = matcher.group(1);
                String input = matcher.group(2);
                String script = scripts.get(scriptName);

                callbacks.printOutput("Found tag: [[" + scriptName + ":" + input + "]]");

                if (script != null) {
                    try {
                        String output = processWithSSE(input, script);
                        if (output != null) {
                            modifiedBody.append(output);
                            bodyModified = true;
                            callbacks.printOutput("Script output: " + output);
                        } else {
                            modifiedBody.append("[[NULL_OUTPUT:" + scriptName + "]]");
                            bodyModified = true;
                            callbacks.printOutput("Script returned null for " + scriptName);
                        }
                    } catch (Exception e) {
                        modifiedBody.append("[[ERROR:" + scriptName + ":" + e.getMessage() + "]]");
                        bodyModified = true;
                        callbacks.printError("Error processing script " + scriptName + ": " + e.getMessage());
                    }
                } else {
                    modifiedBody.append(matcher.group(0));
                    callbacks.printOutput("Script not found for " + scriptName + ", keeping original tag");
                }
                lastEnd = matcher.end();
            }

            // 添加 body 剩余部分
            if (lastEnd < bodyStr.length()) {
                modifiedBody.append(bodyStr.substring(lastEnd));
            }

            // 如果 body 被修改，更新 Content-Length
            if (bodyModified) {
                String modifiedBodyStr = modifiedBody.toString();
                byte[] modifiedBodyBytes = helpers.stringToBytes(modifiedBodyStr);
                int newContentLength = modifiedBodyBytes.length;

                // 更新请求头中的 Content-Length
                java.util.List<String> headers = requestInfo.getHeaders();
                java.util.Iterator<String> iterator = headers.iterator();
                while (iterator.hasNext()) {
                    String header = iterator.next();
                    if (header.toLowerCase().startsWith("content-length:")) {
                        iterator.remove(); // 删除旧的 Content-Length
                    }
                }
                headers.add("Content-Length: " + newContentLength);

                // 重新构建请求
                byte[] newRequest = helpers.buildHttpMessage(headers, modifiedBodyBytes);
                if (newRequest != null) {
                    messageInfo.setRequest(newRequest);
                    callbacks.printOutput("Modified request with updated Content-Length: " + helpers.bytesToString(newRequest));
                } else {
                    callbacks.printError("Failed to build new request");
                }
            } else {
                callbacks.printOutput("No modifications made, keeping original request");
            }

        } catch (Exception e) {
            callbacks.printError("Unexpected error in processHttpMessage: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private String processWithSSE(String input, String script) throws Exception {
        String taskId = UUID.randomUUID().toString();
        JSONObject json = new JSONObject();
        json.put("id", taskId);
        json.put("input", input);
        json.put("script", script);
        json.put("timeout", 10);

        CountDownLatch latch = new CountDownLatch(1);
        resultEvents.put(taskId, latch);
        messages.put(json.toString());

        boolean completed = latch.await(10, TimeUnit.SECONDS);
        String output = completed ? results.remove(taskId) : "Timeout";
        resultEvents.remove(taskId);

        if (!completed) throw new Exception("Processing timeout");
        if (output == null) throw new Exception("No output received");

        this.callbacks.printOutput(String.format("input:%s output:%s", input, output));
        return output;
    }

    class SSEHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            setCORSHeaders(exchange);
            exchange.getResponseHeaders().set("Content-Type", "text/event-stream");
            exchange.getResponseHeaders().set("Cache-Control", "no-cache");
            exchange.getResponseHeaders().set("Connection", "keep-alive");
            exchange.sendResponseHeaders(200, 0);
            OutputStream os = exchange.getResponseBody();
            try {
                while (true) {
                    String msg = messages.take();
                    os.write(("data: " + msg + "\n\n").getBytes());
                    os.flush();
                }
            } catch (InterruptedException e) {
                callbacks.printOutput("SSE interrupted: " + e.getMessage());
            } finally {
                os.close();
            }
        }
    }

    class ResultHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            setCORSHeaders(exchange);
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
                callbacks.printError("Error in /result: " + e.getMessage());
                sendResponse(exchange, 200, "{\"error\": true}");
            }
        }
    }

    class InputHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            setCORSHeaders(exchange);
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "{\"error\": true, \"message\": \"Method not allowed\"}");
                return;
            }
            String requestBody = new String(exchange.getRequestBody().readAllBytes());
            try {
                JSONObject json = new JSONObject(requestBody);
                String taskId = UUID.randomUUID().toString();
                json.put("id", taskId);

                CountDownLatch latch = new CountDownLatch(1);
                resultEvents.put(taskId, latch);
                messages.put(json.toString());

                boolean completed = latch.await(10, TimeUnit.SECONDS);
                String output = completed ? results.remove(taskId) : "Timeout";
                json.put("output", output != null ? output : "Timeout");
                json.put("error", !completed);
                resultEvents.remove(taskId);

                sendResponse(exchange, 200, json.toString());
            } catch (Exception e) {
                callbacks.printError("Error in /input: " + e.getMessage());
                sendResponse(exchange, 200, "{\"error\": true, \"output\": \"Error\"}");
            }
        }
    }

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

    private void sendResponse(HttpExchange exchange, int status, String response) throws IOException {
        exchange.sendResponseHeaders(status, response.length());
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response.getBytes());
        }
    }

    class BurpTab implements ITab {
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
