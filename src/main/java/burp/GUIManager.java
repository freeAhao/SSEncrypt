package burp;

import javax.swing.*;
import java.awt.*;

public class GUIManager {
    private final BurpSSEPlugin plugin;
    private JPanel panel;
    private JTextField portField;
    private JButton startButton, stopButton;
    private JList<String> scriptList;
    private DefaultListModel<String> scriptListModel;
    private JTextField scriptNameField;
    private JTextArea scriptContentArea;
    private final HttpServerManager serverManager;

    public GUIManager(BurpSSEPlugin plugin) {
        this.plugin = plugin;
        this.serverManager = plugin.getServerManager();
    }

    public void setupGUI() {
        panel = new JPanel(new BorderLayout());
        setupServerPanel();
        setupScriptPanel();

        SwingUtilities.invokeLater(() -> {
            plugin.getCallbacks().customizeUiComponent(panel);
        });
        plugin.getCallbacks().addSuiteTab(new BurpTab());
    }

    private void setupServerPanel() {
        JPanel serverPanel = new JPanel(new GridLayout(2, 2));
        portField = new JTextField("8081", 5);
        startButton = new JButton("Start Server");
        stopButton = new JButton("Stop Server");
        stopButton.setEnabled(false);

        serverPanel.add(new JLabel("Port:"));
        serverPanel.add(portField);
        serverPanel.add(startButton);
        serverPanel.add(stopButton);

        startButton.addActionListener(e -> {
            serverManager.startServer(portField.getText());
            updateButtonStates();
        });
        stopButton.addActionListener(e -> {
            serverManager.stopServer();
            updateButtonStates();
        });

        panel.add(serverPanel, BorderLayout.NORTH);
    }

    private void setupScriptPanel() {
        JPanel scriptPanel = new JPanel(new BorderLayout());
        scriptListModel = new DefaultListModel<>();
        scriptList = new JList<>(scriptListModel);
        scriptNameField = new JTextField(20);
        scriptContentArea = new JTextArea(10, 30);

        JPanel scriptControlPanel = new JPanel();
        JButton addScript = new JButton("Add");
        JButton editScript = new JButton("Edit");
        JButton deleteScript = new JButton("Delete");

        scriptControlPanel.add(new JLabel("Script Name:"));
        scriptControlPanel.add(scriptNameField);
        scriptControlPanel.add(addScript);
        scriptControlPanel.add(editScript);
        scriptControlPanel.add(deleteScript);

        ScriptHandler scriptHandler = new ScriptHandler(plugin, scriptListModel, scriptList,
                scriptNameField, scriptContentArea);
        addScript.addActionListener(e -> scriptHandler.addScript());
        editScript.addActionListener(e -> scriptHandler.editScript());
        deleteScript.addActionListener(e -> scriptHandler.deleteScript());
        scriptList.addListSelectionListener(e -> scriptHandler.handleScriptSelection());

        scriptPanel.add(new JScrollPane(scriptList), BorderLayout.WEST);
        scriptPanel.add(new JScrollPane(scriptContentArea), BorderLayout.CENTER);
        scriptPanel.add(scriptControlPanel, BorderLayout.NORTH);

        panel.add(scriptPanel, BorderLayout.CENTER);
    }

    // 更新按钮状态的方法
    private void updateButtonStates() {
        startButton.setEnabled(!plugin.isRunning());
        stopButton.setEnabled(plugin.isRunning());
    }

    public void setRunning(boolean running) {
        startButton.setEnabled(!running);
        stopButton.setEnabled(running);
    }

    class BurpTab implements ITab {
        @Override
        public String getTabCaption() {
            return "SSE Server";
        }

        @Override
        public Component getUiComponent() {
            return panel;
        }
    }

    // 添加 getter 方法以便其他类访问
    public HttpServerManager getServerManager() {
        return serverManager;
    }
}