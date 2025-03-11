package burp;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Map;

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
    private ITextEditor scriptContentArea; // Replaced RSyntaxTextArea with ITextEditor
    private final HttpServerManager serverManager;
    private JTable decryptTable;

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

        // 初始化 Burp 的 ITextEditor
        scriptContentArea = plugin.getCallbacks().createTextEditor();
        scriptContentArea.setEditable(true);

        // 创建表格 - 5列
        String[] columnNames = {"URL Path", "Regex Pattern", "Req/Res", "Decrypt Script", "Enabled"};
        DefaultTableModel tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 4) return Boolean.class; // Enabled column as Boolean for checkbox
                return String.class;
            }
        };
        decryptTable = new JTable(tableModel);
        JScrollPane tableScrollPane = new JScrollPane(decryptTable);
        tableScrollPane.setPreferredSize(new Dimension(400, 200));

        // 配置第2列 (Req/Res) 下拉框
        JComboBox<String> reqResCombo = new JComboBox<>(new String[]{"request", "response"});
        decryptTable.getColumnModel().getColumn(2).setCellEditor(new DefaultCellEditor(reqResCombo));

        // 配置第3列 (Decrypt Script) 下拉框
        JComboBox<String> scriptCombo = new JComboBox<>();
        Map<String, String> decryptScripts = plugin.getDecryptScripts();
        if (decryptScripts != null) {
            decryptScripts.keySet().forEach(scriptCombo::addItem);
        }
        decryptTable.getColumnModel().getColumn(3).setCellEditor(new DefaultCellEditor(scriptCombo));

        // 配置第4列 (Enabled) 复选框 - 默认启用
        decryptTable.getColumnModel().getColumn(4).setCellRenderer(new TableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                JCheckBox checkBox = new JCheckBox();
                checkBox.setSelected(value != null && (Boolean) value);
                checkBox.setHorizontalAlignment(JCheckBox.CENTER);
                return checkBox;
            }
        });

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
                scriptHandler.setEncryptListSelected(true);
            }
        });
        decryptScriptList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                scriptHandler.setEncryptListSelected(false);
            }
        });
        addScript.addActionListener(e -> scriptHandler.addScript());
        deleteScript.addActionListener(e -> scriptHandler.deleteScript());
        encryptScriptList.addListSelectionListener(e -> scriptHandler.handleEncryptScriptSelection());
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
        scriptPanel.add(scriptContentArea.getComponent(), BorderLayout.CENTER); // Use ITextEditor component
        scriptPanel.add(scriptControlPanel, BorderLayout.NORTH);
        scriptPanel.add(tableScrollPane, BorderLayout.SOUTH);
        panel.add(scriptPanel, BorderLayout.CENTER);
    }

    private String readScriptContent(String filename) {
        String scriptContent;
        try {
            InputStream inputStream = getClass().getResourceAsStream("/"+filename);
            if (inputStream == null) {
                throw new FileNotFoundException("Cannot find tampermonkey.js in resources");
            }
            scriptContent = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
            inputStream.close();
        } catch (IOException e) {
            JOptionPane.showMessageDialog(panel,
                    "Error reading tampermonkey.js: " + e.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            scriptContent = "";
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
                writer.write(readScriptContent("tampermonkey.js"));
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

    public void addDecryptRule(String urlPath, String regex, Boolean reqOrRes, String selectedScript) {
        DefaultTableModel model = (DefaultTableModel) decryptTable.getModel();
        model.addRow(new Object[]{urlPath, regex, reqOrRes ? "request" : "response", selectedScript, true}); // Default enabled
    }

    public JTable getDecryptTable() {
        return decryptTable;
    }

    class BurpTab implements ITab {
        @Override
        public String getTabCaption() {
            return "SSEncrypt";
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
