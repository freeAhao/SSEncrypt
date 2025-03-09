package burp;

import org.json.JSONArray;
import org.json.JSONObject;

import javax.swing.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.*;

public class BurpSSEPlugin implements IBurpExtender, IContextMenuFactory, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private HttpServerManager serverManager;
    private GUIManager guiManager;
    protected BlockingQueue<String> messages = new LinkedBlockingQueue<>(100);
    protected ConcurrentHashMap<String, String> results = new ConcurrentHashMap<>();
    protected ConcurrentHashMap<String, CountDownLatch> resultEvents = new ConcurrentHashMap<>();
    protected volatile boolean isRunning = false;
    protected Map<String, String> scripts = new HashMap<>();
    private static final String CONFIG_FILE = "sse_scripts.json";
    private File configFile;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("SSE Server Plugin");
        callbacks.registerContextMenuFactory(this);
        callbacks.registerHttpListener(this);

        configFile = new File(callbacks.getExtensionFilename()).getParentFile();
        configFile = new File(configFile, CONFIG_FILE);

        serverManager = new HttpServerManager(this);
        guiManager = new GUIManager(this);

        loadScriptsFromConfig();
        guiManager.setupGUI();
    }

    public HttpServerManager getServerManager() {
        return serverManager;
    }

    // 保存脚本到配置文件
    public void saveScriptsToConfig() {
        try {
            JSONObject config = new JSONObject();
            JSONArray scriptsArray = new JSONArray();

            for (Map.Entry<String, String> entry : scripts.entrySet()) {
                JSONObject scriptObj = new JSONObject();
                scriptObj.put("name", entry.getKey());
                scriptObj.put("content", entry.getValue());
                scriptsArray.put(scriptObj);
            }

            config.put("scripts", scriptsArray);

            try (FileWriter writer = new FileWriter(configFile)) {
                writer.write(config.toString(2)); // 格式化输出，缩进2个空格
                callbacks.printOutput("Scripts saved to " + configFile.getAbsolutePath());
            }
        } catch (IOException e) {
            callbacks.printError("Error saving scripts to config: " + e.getMessage());
        }
    }

    // 从配置文件加载脚本
    private void loadScriptsFromConfig() {
        if (!configFile.exists()) {
            callbacks.printOutput("No config file found at " + configFile.getAbsolutePath());
            return;
        }

        try {
            String content = new String(Files.readAllBytes(configFile.toPath()));
            JSONObject config = new JSONObject(content);
            JSONArray scriptsArray = config.getJSONArray("scripts");

            scripts.clear();
            for (int i = 0; i < scriptsArray.length(); i++) {
                JSONObject scriptObj = scriptsArray.getJSONObject(i);
                String name = scriptObj.getString("name");
                String scriptContent = scriptObj.getString("content");
                scripts.put(name, scriptContent);
            }
            callbacks.printOutput("Loaded " + scripts.size() + " scripts from config");
        } catch (IOException e) {
            callbacks.printError("Error reading config file: " + e.getMessage());
        } catch (Exception e) {
            callbacks.printError("Error parsing config file: " + e.getMessage());
        }
    }

    // Getter methods
    public IBurpExtenderCallbacks getCallbacks() { return callbacks; }
    public IExtensionHelpers getHelpers() { return helpers; }
    public BlockingQueue<String> getMessages() { return messages; }
    public ConcurrentHashMap<String, String> getResults() { return results; }
    public ConcurrentHashMap<String, CountDownLatch> getResultEvents() { return resultEvents; }
    public Map<String, String> getScripts() { return scripts; }
    public boolean isRunning() { return isRunning; }
    public void setRunning(boolean running) {
        this.isRunning = running;
        this.guiManager.setRunning(running);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        return new ContextMenuHandler(this).createMenuItems(invocation);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        new HttpMessageProcessor(this).processHttpMessage(toolFlag, messageIsRequest, messageInfo);
    }

    public String processWithSSE(String input, String script) throws Exception {
        return new SSEProcessor(this).processWithSSE(input, script);
    }
}