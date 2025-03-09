package burp;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ContextMenuHandler {
    private final BurpSSEPlugin plugin;

    public ContextMenuHandler(BurpSSEPlugin plugin) {
        this.plugin = plugin;
    }

    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
                invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
            List<JMenuItem> menu = new ArrayList<>();
            JMenu scriptMenu = new JMenu("Apply SSE Script");

            for (String scriptName : plugin.getScripts().keySet()) {
                JMenuItem item = new JMenuItem(scriptName);
                item.addActionListener(e -> applyScript(invocation, scriptName));
                scriptMenu.add(item);
            }
            menu.add(scriptMenu);
            return menu;
        }
        return null;
    }

    private void applyScript(IContextMenuInvocation invocation, String scriptName) {
        int[] bounds = invocation.getSelectionBounds();
        IHttpRequestResponse message = invocation.getSelectedMessages()[0];
        byte[] request = message.getRequest();
        String selectedText = new String(Arrays.copyOfRange(request, bounds[0], bounds[1]));
        String taggedText = String.format("[[%s:%s]]", scriptName, selectedText);
        byte[] newRequest = plugin.getHelpers().stringToBytes(
                new String(request, 0, bounds[0]) + taggedText +
                        new String(request, bounds[1], request.length - bounds[1])
        );
        message.setRequest(newRequest);
    }
}