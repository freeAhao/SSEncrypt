package burp;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

public class HttpServerManager {
    private final BurpSSEPlugin plugin;
    private HttpServer server;

    public HttpServerManager(BurpSSEPlugin plugin) {
        this.plugin = plugin;
    }

    public void startServer(String portText) {
        if (plugin.isRunning()) return;

        int port;
        try {
            port = Integer.parseInt(portText.trim());
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Port must be between 1 and 65535");
            }
        } catch (NumberFormatException e) {
            plugin.getCallbacks().printError("Invalid port number: " + portText);
            return;
        }

        try {
            server = HttpServer.create(new InetSocketAddress(port), 10); // 添加 backlog 参数
            server.createContext("/sse", new HttpHandlers.SSEHandler(plugin));
            server.createContext("/result", new HttpHandlers.ResultHandler(plugin));
            server.createContext("/input", new HttpHandlers.InputHandler(plugin));

            server.setExecutor(Executors.newFixedThreadPool(
                    Math.max(4, Runtime.getRuntime().availableProcessors()))
            );

            server.start();
            plugin.setRunning(true);
            plugin.getCallbacks().printOutput("Server started on port " + port);
        } catch (IOException e) {
            plugin.getCallbacks().printError("Error starting server: " + e.getMessage());
        }
    }

    public void stopServer() {
        if (!plugin.isRunning() || server == null) return;
        server.stop(0);
        plugin.setRunning(false);
        plugin.getCallbacks().printOutput("Server stopped");
    }
}