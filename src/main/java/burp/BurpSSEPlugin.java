package burp;

import org.json.JSONArray;
import org.json.JSONObject;

import javax.swing.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.*;

public class BurpSSEPlugin implements IBurpExtender, IExtensionStateListener, IContextMenuFactory, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private HttpServerManager serverManager;
    private GUIManager guiManager;
    protected BlockingQueue<String> messages = new LinkedBlockingQueue<>(100);
    protected ConcurrentHashMap<String, String> results = new ConcurrentHashMap<>();
    protected ConcurrentHashMap<String, CountDownLatch> resultEvents = new ConcurrentHashMap<>();
    protected volatile boolean isRunning = false;
    protected Map<String, String> encryptScripts = new HashMap<>();
    protected Map<String, String> decryptScripts = new HashMap<>();
    private static final String CONFIG_FILE = "sse_scripts.json";
    private File configFile;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("SSE Server Plugin");
        callbacks.registerExtensionStateListener(this);
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

    public void saveScriptsToConfig() {
        try {
            JSONObject config = new JSONObject();

            // 保存加密脚本
            JSONArray encryptScriptsArray = new JSONArray();
            for (Map.Entry<String, String> entry : encryptScripts.entrySet()) {
                JSONObject scriptObj = new JSONObject();
                scriptObj.put("name", entry.getKey());
                scriptObj.put("content", entry.getValue());
                encryptScriptsArray.put(scriptObj);
            }

            // 保存解密脚本
            JSONArray decryptScriptsArray = new JSONArray();
            for (Map.Entry<String, String> entry : decryptScripts.entrySet()) {
                JSONObject scriptObj = new JSONObject();
                scriptObj.put("name", entry.getKey());
                scriptObj.put("content", entry.getValue());
                decryptScriptsArray.put(scriptObj);
            }

            config.put("encrypt_scripts", encryptScriptsArray);
            config.put("decrypt_scripts", decryptScriptsArray);

            try (FileWriter writer = new FileWriter(configFile)) {
                writer.write(config.toString(2));
                callbacks.printOutput("Scripts saved to " + configFile.getAbsolutePath());
            }
        } catch (IOException e) {
            callbacks.printError("Error saving scripts to config: " + e.getMessage());
        }
    }

    private void loadScriptsFromConfig() {
        if (!configFile.exists()) {
            callbacks.printOutput("No config file found at " + configFile.getAbsolutePath());
            return;
        }

        try {
            String content = new String(Files.readAllBytes(configFile.toPath()));
            JSONObject config = new JSONObject(content);

            encryptScripts.clear();
            decryptScripts.clear();

            // 加载加密脚本
            JSONArray encryptScriptsArray = config.optJSONArray("encrypt_scripts");
            if (encryptScriptsArray != null) {
                for (int i = 0; i < encryptScriptsArray.length(); i++) {
                    JSONObject scriptObj = encryptScriptsArray.getJSONObject(i);
                    String name = scriptObj.getString("name");
                    String scriptContent = scriptObj.getString("content");
                    encryptScripts.put(name, scriptContent);
                }
            }

            // 加载解密脚本
            JSONArray decryptScriptsArray = config.optJSONArray("decrypt_scripts");
            if (decryptScriptsArray != null) {
                for (int i = 0; i < decryptScriptsArray.length(); i++) {
                    JSONObject scriptObj = decryptScriptsArray.getJSONObject(i);
                    String name = scriptObj.getString("name");
                    String scriptContent = scriptObj.getString("content");
                    decryptScripts.put(name, scriptContent);
                }
            }

            callbacks.printOutput("Loaded " + encryptScripts.size() + " encrypt scripts and " +
                    decryptScripts.size() + " decrypt scripts from config");
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
    public Map<String, String> getEncryptScripts() { return encryptScripts; }
    public Map<String, String> getDecryptScripts() { return decryptScripts; }
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

    @Override
    public void extensionUnloaded() {
        this.serverManager.stopServer();
    }
}
