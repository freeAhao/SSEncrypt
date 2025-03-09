package burp;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// 支持多层标签嵌套，从最里面的嵌套开始处理
public class HttpMessageProcessor {
    private final BurpSSEPlugin plugin;

    public HttpMessageProcessor(BurpSSEPlugin plugin) {
        this.plugin = plugin;
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!this.plugin.isRunning || !messageIsRequest || !(toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER ||
                toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER)) {
            return;
        }

        try {
            byte[] request = messageInfo.getRequest();
            if (request == null) {
                plugin.getCallbacks().printError("Request is null");
                return;
            }

            IRequestInfo requestInfo = plugin.getHelpers().analyzeRequest(request);
            String requestStr = plugin.getHelpers().bytesToString(request);

            int bodyOffset = requestInfo.getBodyOffset();
            String headersStr = requestStr.substring(0, bodyOffset);
            String bodyStr = requestStr.substring(bodyOffset);

            String modifiedHeaders = resolveNestedTags(headersStr);
            String modifiedBody = resolveNestedTags(bodyStr);

            if (!modifiedHeaders.equals(headersStr) || !modifiedBody.equals(bodyStr)) {
                updateRequest(messageInfo, plugin.getHelpers().analyzeRequest(modifiedHeaders.getBytes()).getHeaders(), modifiedBody);
            }
        } catch (Exception e) {
            plugin.getCallbacks().printError("Unexpected error in processHttpMessage: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private String resolveNestedTags(String input) throws Exception {
        String regex = "\\[\\[([^:]+?):((?:[^\\[\\]]|\\[\\[(?:[^\\[\\]]|\\[\\[.*?\\]\\])*?\\]\\])*?)\\]\\]";
        Pattern pattern = Pattern.compile(regex);

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
                String script = plugin.getScripts().get(scriptName);

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
