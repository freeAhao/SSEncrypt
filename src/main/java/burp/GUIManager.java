package burp;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class GUIManager {
    private final BurpSSEPlugin plugin;
    private JPanel panel;
    private JTextField portField;
    private JButton startButton, stopButton, downloadScriptButton;
    private JList<String> scriptList;
    private DefaultListModel<String> scriptListModel;
    private JTextField scriptNameField;
    private RSyntaxTextArea scriptContentArea;
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

        // 初始化 RSyntaxTextArea
//        javax.swing.text.JTextComponent/removeKeymap "RTextAreaKeymap"
        JTextComponent.removeKeymap("RTextAreaKeymap");
        scriptContentArea = new RSyntaxTextArea(10, 30);

        scriptContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT); // 设置语法高亮
        scriptContentArea.setCodeFoldingEnabled(true); // 启用代码折叠
        scriptContentArea.setEditable(true); // 确保可编辑

        // 将 RSyntaxTextArea 包裹在 RTextScrollPane 中
        RTextScrollPane scrollPane = new RTextScrollPane(scriptContentArea);
        scrollPane.setBorder(BorderFactory.createEmptyBorder()); // 可选：设置边框

        JPanel scriptControlPanel = new JPanel();
        JButton addScript = new JButton("Add");
        JButton editScript = new JButton("Edit");
        JButton deleteScript = new JButton("Delete");
        downloadScriptButton = new JButton("TamperMonkey Script");

        scriptControlPanel.add(new JLabel("Script Name:"));
        scriptControlPanel.add(scriptNameField);
        scriptControlPanel.add(addScript);
        scriptControlPanel.add(editScript);
        scriptControlPanel.add(deleteScript);
        scriptControlPanel.add(downloadScriptButton);

        ScriptHandler scriptHandler = new ScriptHandler(plugin, scriptListModel, scriptList,
                scriptNameField, scriptContentArea, addScript);
        scriptNameField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                super.keyReleased(e);
                if (scriptHandler.contains(scriptNameField.getText())) {
                    addScript.setText("Update");
                } else {
                    addScript.setText("Add");
                }
            }
        });
        addScript.addActionListener(e -> scriptHandler.addScript());
        editScript.addActionListener(e -> scriptHandler.editScript());
        deleteScript.addActionListener(e -> scriptHandler.deleteScript());
        scriptList.addListSelectionListener(e -> scriptHandler.handleScriptSelection());

        downloadScriptButton.addActionListener(e -> downloadScript());

        scriptPanel.add(new JScrollPane(scriptList), BorderLayout.WEST);
        scriptPanel.add(scrollPane, BorderLayout.CENTER); // 使用 RTextScrollPane
        scriptPanel.add(scriptControlPanel, BorderLayout.NORTH);

        panel.add(scriptPanel, BorderLayout.CENTER);
    }
    private String readScriptContent() {
        String scriptContent;
        try {
            // 从资源目录读取 tampermonkey.js
            InputStream inputStream = getClass().getResourceAsStream("/tampermonkey.js");
            if (inputStream == null) {
                throw new FileNotFoundException("Cannot find tampermonkey.js in resources");
            }

            // 将 InputStream 转换为字符串
            scriptContent = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
            inputStream.close();
        } catch (IOException e) {
            JOptionPane.showMessageDialog(panel,
                    "Error reading tampermonkey.js: " + e.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            scriptContent = ""; // 设置默认空值以防后续操作失败
        }
        return scriptContent;
    }
    private void downloadScript() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setSelectedFile(new File("script.js"));
        int option = fileChooser.showSaveDialog(panel);
        if (option == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (FileWriter writer = new FileWriter(file)) {
                writer.write(readScriptContent());
                JOptionPane.showMessageDialog(panel, "Script saved successfully.", "Success", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(panel, "Error saving script: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

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

    public HttpServerManager getServerManager() {
        return serverManager;
    }
}
