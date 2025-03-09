package burp;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;

import javax.swing.*;

public class ScriptHandler {
    private final BurpSSEPlugin plugin;
    private final DefaultListModel<String> scriptListModel;
    private final JList<String> scriptList;
    private final JTextField scriptNameField;
    private final JTextArea scriptContentArea;

    private final JButton addScript;

    public ScriptHandler(BurpSSEPlugin plugin, DefaultListModel<String> scriptListModel,
                         JList<String> scriptList, JTextField scriptNameField, RSyntaxTextArea scriptContentArea, JButton addScript) {
        this.plugin = plugin;
        this.scriptListModel = scriptListModel;
        this.scriptList = scriptList;
        this.scriptNameField = scriptNameField;
        this.scriptContentArea = scriptContentArea;
        this.addScript = addScript;

        loadScriptsToList();
    }

    public void addScript() {
        String name = scriptNameField.getText().trim();
        String content = scriptContentArea.getText().trim();
        if (!name.isEmpty() && !content.isEmpty()) {
            plugin.getScripts().put(name, content);
            if (!scriptListModel.contains(name)) {
                scriptListModel.addElement(name);
            }
            plugin.getCallbacks().printOutput("Script added: " + name);
            plugin.saveScriptsToConfig();
        }
    }

    public void editScript() {
        String selected = scriptList.getSelectedValue();
        if (selected != null) {
            String newName = scriptNameField.getText().trim();
            String content = scriptContentArea.getText().trim();
            if (!newName.isEmpty() && !content.isEmpty()) {
                plugin.getScripts().remove(selected);
                plugin.getScripts().put(newName, content);
                int index = scriptListModel.indexOf(selected);
                scriptListModel.set(index, newName);
                plugin.getCallbacks().printOutput("Script updated: " + newName);
                plugin.saveScriptsToConfig();
            }
        }
    }

    public void deleteScript() {
        String selected = scriptList.getSelectedValue();
        if (selected != null) {
            plugin.getScripts().remove(selected);
            scriptListModel.removeElement(selected);
            scriptNameField.setText("");
            scriptContentArea.setText("");
            plugin.getCallbacks().printOutput("Script deleted: " + selected);
            plugin.saveScriptsToConfig();
        }
    }

    public void handleScriptSelection() {
        String selected = scriptList.getSelectedValue();
        if (selected != null) {
            scriptNameField.setText(selected);
            scriptContentArea.setText(plugin.getScripts().get(selected));
            addScript.setText("Update");
        }
    }

    private void loadScriptsToList() {
        scriptListModel.clear();
        for (String scriptName : plugin.getScripts().keySet()) {
            scriptListModel.addElement(scriptName);
        }
    }

    public boolean contains(String scripName){
        return scriptListModel.contains(scripName);
    }
}