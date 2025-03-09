package burp;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class GUIManager {
    private final BurpSSEPlugin plugin;
    private JPanel panel;
    private JTextField portField;
    private JButton startButton, stopButton, downloadScriptButton;
    private JList<String> encryptScriptList;
    private JList<String> decryptScriptList;
    private DefaultListModel<String> encryptScriptListModel;
    private DefaultListModel<String> decryptScriptListModel;
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

        // 加密脚本列表部分
        encryptScriptListModel = new DefaultListModel<>();
        encryptScriptList = new JList<>(encryptScriptListModel);
        JLabel encryptLabel = new JLabel("Encryption Scripts:");

        // 解密脚本列表部分
        decryptScriptListModel = new DefaultListModel<>();
        decryptScriptList = new JList<>(decryptScriptListModel);
        JLabel decryptLabel = new JLabel("Decryption Scripts:");

        scriptNameField = new JTextField(20);

        // 初始化 RSyntaxTextArea
        JTextComponent.removeKeymap("RTextAreaKeymap");
        scriptContentArea = new RSyntaxTextArea(10, 30);
        scriptContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
        scriptContentArea.setCodeFoldingEnabled(true);
        scriptContentArea.setEditable(true);

        RTextScrollPane scrollPane = new RTextScrollPane(scriptContentArea);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());

        // 创建表格
        String[] columnNames = {"URL Path", "Regex Pattern", "Decrypt Script"};
        Object[][] data = {}; // 初始空数据
        JTable decryptTable = new JTable(new DefaultTableModel(data, columnNames));
        JScrollPane tableScrollPane = new JScrollPane(decryptTable);
        tableScrollPane.setPreferredSize(new Dimension(400, 100));

        // 控制面板
        JPanel scriptControlPanel = new JPanel();
        JButton addScript = new JButton("Add");
        JButton deleteScript = new JButton("Delete");
        downloadScriptButton = new JButton("TamperMonkey Script");

        scriptControlPanel.add(new JLabel("Script Name:"));
        scriptControlPanel.add(scriptNameField);
        scriptControlPanel.add(addScript);
        scriptControlPanel.add(deleteScript);
        scriptControlPanel.add(downloadScriptButton);

        ScriptHandler scriptHandler = new ScriptHandler(plugin,
                encryptScriptListModel, encryptScriptList,
                decryptScriptListModel, decryptScriptList,
                scriptNameField, scriptContentArea, addScript);
        scriptNameField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                if (scriptHandler.contains(scriptNameField.getText())) {
                    addScript.setText("Update");
                } else {
                    addScript.setText("Add");
                }
            }
        });
        encryptScriptList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                scriptHandler.setEncryptListSelected(true); // 点击时设置为true
            }
        });

        decryptScriptList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                scriptHandler.setEncryptListSelected(false); // 点击时设置为false
            }
        });
        addScript.addActionListener(e -> scriptHandler.addScript());
        deleteScript.addActionListener(e -> scriptHandler.deleteScript());
        encryptScriptList.addListSelectionListener(e -> scriptHandler.handleEncryptScriptSelection());

        // 处理解密脚本
        decryptScriptList.addListSelectionListener(e -> scriptHandler.handleDecryptScriptSelection());

        downloadScriptButton.addActionListener(e -> downloadScript());

        // 布局设置
        JPanel listsPanel = new JPanel(new GridLayout(2, 1));
        JPanel encryptPanel = new JPanel(new BorderLayout());
        encryptPanel.add(encryptLabel, BorderLayout.NORTH);
        encryptPanel.add(new JScrollPane(encryptScriptList), BorderLayout.CENTER);

        JPanel decryptPanel = new JPanel(new BorderLayout());
        decryptPanel.add(decryptLabel, BorderLayout.NORTH);
        decryptPanel.add(new JScrollPane(decryptScriptList), BorderLayout.CENTER);

        listsPanel.add(encryptPanel);
        listsPanel.add(decryptPanel);

        scriptPanel.add(listsPanel, BorderLayout.WEST);
        scriptPanel.add(scrollPane, BorderLayout.CENTER);
        scriptPanel.add(scriptControlPanel, BorderLayout.NORTH);
        scriptPanel.add(tableScrollPane, BorderLayout.SOUTH); // 添加表格在底部
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
