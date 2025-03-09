package burp;

import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// TODO: 3/9/25 支持多层标签嵌套，从最里面的嵌套开始处理

public class HttpMessageProcessor {
    private final BurpSSEPlugin plugin;

    public HttpMessageProcessor(BurpSSEPlugin plugin) {
        this.plugin = plugin;
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest || !(toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER ||
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

            String modifiedHeaders = processHeaders(headersStr);
            String modifiedBody = processBody(bodyStr);

            if (!modifiedHeaders.equals(headersStr) || !modifiedBody.equals(bodyStr)) {
                updateRequest(messageInfo, plugin.getHelpers().analyzeRequest(modifiedHeaders.getBytes()).getHeaders(), modifiedBody);
            }
        } catch (Exception e) {
            plugin.getCallbacks().printError("Unexpected error in processHttpMessage: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private String processHeaders(String headersStr) throws Exception {
        String regex = "\\[\\[(.+?):(.+?)\\]\\]";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(headersStr);

        StringBuilder modifiedHeaders = new StringBuilder();
        int lastEnd = 0;

        while (matcher.find()) {
            modifiedHeaders.append(headersStr.substring(lastEnd, matcher.start()));
            String scriptName = matcher.group(1);
            String input = matcher.group(2);
            String script = plugin.getScripts().get(scriptName);

            if (script != null) {
                String output = plugin.processWithSSE(input, script);
                modifiedHeaders.append(output != null ? output : "[[NULL_OUTPUT:" + scriptName + "]]" );
            } else {
                modifiedHeaders.append(matcher.group(0));
            }
            lastEnd = matcher.end();
        }
        modifiedHeaders.append(headersStr.substring(lastEnd));
        return modifiedHeaders.toString();
    }

    private String processBody(String bodyStr) throws Exception {
        String regex = "\\[\\[(.+?):(.+?)\\]\\]";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(bodyStr);

        StringBuilder modifiedBody = new StringBuilder();
        int lastEnd = 0;

        while (matcher.find()) {
            modifiedBody.append(bodyStr.substring(lastEnd, matcher.start()));
            String scriptName = matcher.group(1);
            String input = matcher.group(2);
            String script = plugin.getScripts().get(scriptName);

            if (script != null) {
                String output = plugin.processWithSSE(input, script);
                modifiedBody.append(output != null ? output : "[[NULL_OUTPUT:" + scriptName + "]]" );
            } else {
                modifiedBody.append(matcher.group(0));
            }
            lastEnd = matcher.end();
        }
        modifiedBody.append(bodyStr.substring(lastEnd));
        return modifiedBody.toString();
    }

    private void updateRequest(IHttpRequestResponse messageInfo, List<String> headers, String modifiedBodyStr) {
        byte[] modifiedBodyBytes = plugin.getHelpers().stringToBytes(modifiedBodyStr);
        Iterator<String> iterator = headers.iterator();
        while (iterator.hasNext()) {
            String header = iterator.next();
            if (header.toLowerCase().startsWith("content-length:")) {
                iterator.remove();
            }
        }
        headers.add("Content-Length: " + modifiedBodyBytes.length);

        byte[] newRequest = plugin.getHelpers().buildHttpMessage(headers, modifiedBodyBytes);
        if (newRequest != null) {
            messageInfo.setRequest(newRequest);
        }
    }
}
