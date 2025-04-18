package burp;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// 支持多层标签嵌套，从最里面的嵌套开始处理
public class HttpMessageProcessor {
    private final BurpSSEPlugin plugin;

    public HttpMessageProcessor(BurpSSEPlugin plugin) {
        this.plugin = plugin;
    }

    private boolean checkMatchingRule(boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        IRequestInfo requestInfo = this.plugin.getHelpers().analyzeRequest(messageInfo);

        JTable ruleTable = plugin.getGuiManager().getRuleTable();
        String messageContent = null;
        if (messageIsRequest) {
            messageContent = new String(messageInfo.getRequest(), StandardCharsets.UTF_8);
        }  else {
            messageContent = new String(messageInfo.getResponse(), StandardCharsets.UTF_8);
        }

        for (int i = 0; i < ruleTable.getRowCount(); i++) {
            Boolean enabled = (Boolean) ruleTable.getValueAt(i, 5);
            if (enabled != null && !enabled) {continue;}
            String encDec = (String) ruleTable.getValueAt(i, 3);
            if (encDec != null && !encDec.equals("encrypt")) {continue;}

            String urlPath = (String) ruleTable.getValueAt(i, 0);
            String regex = (String) ruleTable.getValueAt(i, 1);
            String type = (String) ruleTable.getValueAt(i, 2);
            if (requestInfo.getUrl().getPath().equals(urlPath)) {
                if ((messageIsRequest && "request".equals(type)) || (!messageIsRequest && "response".equals(type))) {
                    try {
                        Pattern pattern = Pattern.compile(regex, Pattern.DOTALL);
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


    private String encryptData(String originalMessage, Matcher matcher, Pattern pattern, String scriptName) throws Exception {
        String script = plugin.getEncryptScripts().get(scriptName);
        if (script == null) {
            throw new Exception("Encrypt script '" + scriptName + "' not found.");
        }

        if (matcher.groupCount() < 1) {
            throw new Exception("Regex pattern '" + pattern.pattern() + "' does not contain a capture group (group 1).");
        }

        String decryptedData = matcher.group(1);
        String encryptedData = plugin.processWithSSE(decryptedData, script);

        StringBuffer result = new StringBuffer();
        matcher.reset();
        while (matcher.find()) {
            String fullMatch = matcher.group(0);
            String group1 = matcher.group(1);
            String replacement = fullMatch.substring(0, matcher.start(1) - matcher.start()) +
                    encryptedData +
                    fullMatch.substring(matcher.end(1) - matcher.start());
            matcher.appendReplacement(result, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(result);

        return result.toString();
    }

    private String encryptRequest(IRequestInfo requestInfo, String currentRequest) throws Exception {
        JTable ruleTable = plugin.getGuiManager().getRuleTable();
        boolean matchedRule;
        ArrayList<Integer> usedRules = new ArrayList<>();

        // Recursive encryption loop
        do {
            matchedRule = false;
            for (int i = 0; i < ruleTable.getRowCount(); i++) {
                Boolean enabled = (Boolean) ruleTable.getValueAt(i, 5);
                String encDec = (String) ruleTable.getValueAt(i, 3);
                if (!encDec.equals("encrypt")){
                    continue;
                }
                if (enabled != null && !enabled) {continue;}
                String urlPath = (String) ruleTable.getValueAt(i, 0);
                String regex = (String) ruleTable.getValueAt(i, 1);
                String type = (String) ruleTable.getValueAt(i, 2);
                String scriptName = (String) ruleTable.getValueAt(i, 4);
                if (usedRules.contains(i)) {
                    continue;
                }

                if (requestInfo.getUrl().getPath().equals(urlPath)) {
                    if (("request".equals(type))) {
                        Pattern pattern = Pattern.compile(regex, Pattern.DOTALL);
                        Matcher matcher = pattern.matcher(currentRequest);
                        if (matcher.find()) {
                            usedRules.add(i);
                            currentRequest = encryptData(currentRequest, matcher, pattern, scriptName);
                            matchedRule = true;
                            break;
                        }
                    }
                }
            }
        } while (matchedRule);

        return currentRequest;
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!this.plugin.isRunning || !messageIsRequest) {
            return;
        }
        byte[] request = messageInfo.getRequest();
        IHttpService httpService = messageInfo.getHttpService();

        //规则解析 针对代理 插件 扫描器
        if (checkMatchingRule(messageIsRequest, messageInfo) && (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY ||
                toolFlag == IBurpExtenderCallbacks.TOOL_EXTENDER || toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER)) {

            // MessageProcessor只能同步处理解密
            try {
                if (request == null) {
                    return;
                }

                IRequestInfo requestInfo = plugin.getHelpers().analyzeRequest(httpService, request);
                String currentRequest = new String(request);

                String modifiedRequest = encryptRequest(requestInfo, currentRequest);

                // 加密完成后更新显示
                if (!modifiedRequest.equals(currentRequest)) {
                    int bodyOffset = plugin.getHelpers().analyzeRequest(modifiedRequest.getBytes()).getBodyOffset();
                    String modifiedBody = modifiedRequest.substring(bodyOffset);
                    List<String> headers = plugin.getHelpers().analyzeRequest(modifiedRequest.getBytes()).getHeaders();
                    updateRequest(messageInfo, headers, modifiedBody);
                    messageInfo.setHighlight("green");
                    messageInfo.setComment("SSEncrypt");
                }
            } catch (Exception e) {
                plugin.getCallbacks().printError("Error processing http message: " + e.getMessage());
            }
        }

        // 标签解析 针对Repeater Intruder
        if (toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER || toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER) {
            try {
                if (request == null) {
                    plugin.getCallbacks().printError("Request is null");
                    return;
                }

                IRequestInfo requestInfo = plugin.getHelpers().analyzeRequest(httpService, request);
//            String requestStr = plugin.getHelpers().bytesToString(request);
                String requestStr = new String(request);

                int bodyOffset = requestInfo.getBodyOffset();
                String headersStr = requestStr.substring(0, bodyOffset);
                String bodyStr = requestStr.substring(bodyOffset);

                String modifiedHeaders = resolveNestedTags(headersStr);
                String modifiedBody = resolveNestedTags(bodyStr);

                if (!modifiedHeaders.equals(headersStr) || !modifiedBody.equals(bodyStr)) {
                    updateRequest(messageInfo, plugin.getHelpers().analyzeRequest(modifiedHeaders.getBytes()).getHeaders(), modifiedBody);
                    messageInfo.setHighlight("green");
                    messageInfo.setComment("SSEncrypt");
                }
            } catch (Exception e) {
                plugin.getCallbacks().printError("Unexpected error in processHttpMessage: " + e.getMessage());
                e.printStackTrace();
            }

        }
    }

    private String resolveNestedTags(String input) throws Exception {
        String regex = "\\[\\[([^:]+?):((?:[^\\[\\]]|\\[\\[(?:[^\\[\\]]|\\[\\[.*?\\]\\])*?\\]\\])*?)\\]\\]";
        Pattern pattern = Pattern.compile(regex, Pattern.DOTALL);

        while (true) {
            Matcher matcher = pattern.matcher(input);
            boolean found = false;
            StringBuffer sb = new StringBuffer();

            while (matcher.find()) {
                found = true;
                String fullMatch = matcher.group(0);  // 确保完整匹配
                String scriptName = matcher.group(1);
                String nestedInput = matcher.group(2);

                // 递归解析嵌套内容
                String resolvedInput = resolveNestedTags(nestedInput);
                String script = plugin.getEncryptScripts().get(scriptName);

                String output;
                if (script != null) {
                    output = plugin.processWithSSE(resolvedInput, script);
                    if (output == null) {
                        output = "[[NULL_OUTPUT:" + scriptName + "]]";
                    }
                } else {
                    output = fullMatch;
                }

                matcher.appendReplacement(sb, Matcher.quoteReplacement(output));
            }
            matcher.appendTail(sb);
            input = sb.toString();

            if (!found) break;  // 如果没有更多匹配，则退出循环
        }
        return input;
    }

    private void updateRequest(IHttpRequestResponse messageInfo, List<String> headers, String modifiedBodyStr) {
        byte[] modifiedBodyBytes = plugin.getHelpers().stringToBytes(modifiedBodyStr);
        headers.removeIf(header -> header.toLowerCase().startsWith("content-length:"));
        headers.add("Content-Length: " + modifiedBodyBytes.length);

        byte[] newRequest = plugin.getHelpers().buildHttpMessage(headers, modifiedBodyBytes);
        if (newRequest != null) {
            messageInfo.setRequest(newRequest);
        }
    }
}
