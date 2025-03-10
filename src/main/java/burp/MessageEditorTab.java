package burp;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MessageEditorTab implements IMessageEditorTab {
    private final BurpSSEPlugin plugin;
    private final IMessageEditorController controller;
    private IMessageEditor messageEditor; // Replace RSyntaxTextArea with Burp's IMessageEditor
    private boolean isModified = false;
    private byte[] currentContent;
    private boolean isRequest;
    private String lastDecryptedMessage; // Cache last decrypted result to avoid redundant decryption

    public MessageEditorTab(BurpSSEPlugin plugin, IMessageEditorController controller) {
        this.plugin = plugin;
        this.controller = controller;
        // Initialize the Burp-provided message editor
        this.messageEditor = plugin.getCallbacks().createMessageEditor(controller, false); // false = read-only
    }

    @Override
    public String getTabCaption() {
        return "Decrypted Message";
    }

    @Override
    public Component getUiComponent() {
        // Return the UI component of the Burp message editor
        if (currentContent != null && lastDecryptedMessage != null) {
            setTextSafely(lastDecryptedMessage);
        }
        return messageEditor.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return checkMatchingRule(content, isRequest);
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        this.currentContent = content;
        this.isRequest = isRequest;
        loadDecryptedData();
    }

    @Override
    public byte[] getMessage() {
        return messageEditor != null ? messageEditor.getMessage() : new byte[0];
    }

    @Override
    public boolean isModified() {
        return isModified;
    }

    @Override
    public byte[] getSelectedData() {
        return messageEditor != null ? messageEditor.getSelectedData() : null;
    }

    private boolean checkMatchingRule(byte[] content, boolean isRequest) {
        IHttpService httpService = controller.getHttpService();
        byte[] request = controller.getRequest();
        if (request == null) {
            return false;
        }

        IRequestInfo requestInfo = plugin.getHelpers().analyzeRequest(httpService, request);
        String url = requestInfo.getUrl().toString();
        JTable decryptTable = plugin.getGuiManager().getDecryptTable();
        String messageContent = new String(content, StandardCharsets.UTF_8);

        for (int i = 0; i < decryptTable.getRowCount(); i++) {
            String urlPath = (String) decryptTable.getValueAt(i, 0);
            String regex = (String) decryptTable.getValueAt(i, 1);
            String type = (String) decryptTable.getValueAt(i, 2);

            if (requestInfo.getUrl().getPath().equals(urlPath)) {
                if ((isRequest && "request".equals(type)) || (!isRequest && "response".equals(type))) {
                    try {
                        Pattern pattern = Pattern.compile(regex);
                        Matcher matcher = pattern.matcher(messageContent);
                        if (matcher.find()) {
                            return true;
                        }
                    } catch (Exception e) {
                        plugin.getCallbacks().printError("Invalid regex pattern at row " + i + ": " + e.getMessage());
                    }
                }
            }
        }
        return false;
    }

    private void loadDecryptedData() {
        if (currentContent == null) {
            setTextSafely("No content available.");
            return;
        }

        IHttpService httpService = controller.getHttpService();
        byte[] request = controller.getRequest();
        if (request == null) {
            setTextSafely("No request data available to determine URL.");
            return;
        }

        IRequestInfo requestInfo = plugin.getHelpers().analyzeRequest(httpService, request);
        String url = requestInfo.getUrl().toString();
        JTable decryptTable = plugin.getGuiManager().getDecryptTable();
        String messageContent = new String(currentContent, StandardCharsets.UTF_8);
        String currentResult = messageContent;
        boolean matchedRule;
        ArrayList<Integer> usedRules = new ArrayList<>();

        // Recursive decryption loop
        do {
            matchedRule = false;
            for (int i = 0; i < decryptTable.getRowCount(); i++) {
                String urlPath = (String) decryptTable.getValueAt(i, 0);
                String regex = (String) decryptTable.getValueAt(i, 1);
                String type = (String) decryptTable.getValueAt(i, 2);
                String scriptName = (String) decryptTable.getValueAt(i, 3);
                if (usedRules.contains(i)) {
                    continue;
                }

                if (url.contains(urlPath)) {
                    if ((isRequest && "request".equals(type)) || (!isRequest && "response".equals(type))) {
                        try {
                            Pattern pattern = Pattern.compile(regex);
                            Matcher matcher = pattern.matcher(currentResult);
                            if (matcher.find()) {
                                usedRules.add(i);
                                currentResult = decryptData(currentResult, matcher, pattern, scriptName);
                                matchedRule = true;
                                lastDecryptedMessage = currentResult; // Update cached result
                                break; // Break to start new iteration with updated content
                            }
                        } catch (Exception e) {
                            setTextSafely("Error decrypting data: " + e.getMessage());
                            return;
                        }
                    }
                }
            }
        } while (matchedRule); // Continue until no more rules match

        setTextSafely(currentResult);
    }

    private String decryptData(String originalMessage, Matcher matcher, Pattern pattern, String scriptName) throws Exception {
        String script = plugin.getDecryptScripts().get(scriptName);
        if (script == null) {
            throw new Exception("Decrypt script '" + scriptName + "' not found.");
        }

        if (matcher.groupCount() < 1) {
            throw new Exception("Regex pattern '" + pattern.pattern() + "' does not contain a capture group (group 1).");
        }

        String encryptedData = matcher.group(1);
        String decryptedData = plugin.processWithSSE(encryptedData, script);

        StringBuffer result = new StringBuffer();
        matcher.reset();
        while (matcher.find()) {
            String fullMatch = matcher.group(0);
            String group1 = matcher.group(1);
            String replacement = fullMatch.substring(0, matcher.start(1) - matcher.start()) +
                    decryptedData +
                    fullMatch.substring(matcher.end(1) - matcher.start());
            matcher.appendReplacement(result, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(result);

        return result.toString();
    }

    private void setTextSafely(String text) {
        if (messageEditor != null) {
            SwingUtilities.invokeLater(() -> {
                messageEditor.setMessage(text.getBytes(StandardCharsets.UTF_8), isRequest);
            });
        } else {
            plugin.getCallbacks().printOutput("Message editor is null, cannot set text: " + text);
        }
    }
}