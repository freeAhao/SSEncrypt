package burp;

import com.sun.net.httpserver.HttpServer;
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
        try {
            int port = Integer.parseInt(portText.trim());
            server = HttpServer.create(new InetSocketAddress(port), 0);

            server.createContext("/sse", new HttpHandlers.SSEHandler(plugin));
            server.createContext("/result", new HttpHandlers.ResultHandler(plugin));
            server.createContext("/input", new HttpHandlers.InputHandler(plugin));

            server.setExecutor(Executors.newCachedThreadPool());
            server.start();
            plugin.setRunning(true);
            plugin.getCallbacks().printOutput("Server started on port " + port);
        } catch (Exception e) {
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