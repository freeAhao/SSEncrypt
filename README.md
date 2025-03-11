# Burp SSE Plugin

**Burp SSE Plugin** is a Burp Suite extension designed to enhance HTTP request and response manipulation by integrating Server-Sent Events (SSE) and custom encryption/decryption scripts. This plugin provides a flexible framework for processing HTTP messages in real-time, allowing security researchers and pentesters to automate encryption/decryption workflows, manage scripts, and visualize decrypted data within Burp Suite.

The plugin leverages an embedded HTTP server to handle SSE communication, supports dynamic script management, and offers a user-friendly GUI for configuration and rule management.

## Features

- **Embedded HTTP Server**: Runs an SSE server within Burp Suite to process HTTP messages dynamically.
- **Custom Encryption/Decryption Scripts**: Allows users to define and manage JavaScript-based encryption and decryption scripts stored in a JSON config file (`sse_scripts.json`).
- **Context Menu Integration**: Apply encryption scripts to selected HTTP request text and add decryption rules directly from the context menu.
- **Message Editor Tab**: Displays decrypted HTTP request/response content in a dedicated tab based on predefined rules.
- **GUI Management**: Manage scripts, server settings, and decryption rules via an intuitive interface in the Burp Suite tab "SSE Server".
- **Dynamic Rule-Based Decryption**: Automatically decrypts HTTP messages matching user-defined URL paths and regex patterns.
- **TamperMonkey Script Export**: Download a pre-configured TamperMonkey script for client-side testing.
- **Real-Time Processing**: Processes nested encryption tags (`[[scriptName:content]]`) in HTTP requests within Repeater and Intruder tools.

## Requirements

- **Burp Suite Professional or Community Edition** (tested with Burp Suite 2023.x and later).
- **Java 8 or higher** (compatible with Burp Suite's Jython/embedded JVM).
- Dependencies:
  - `org.json` (for JSON handling, included in the code).
  - Burp Suite Extender API (provided by Burp Suite).

## Installation

1. **Compile the Plugin**:
   - Clone this repository:
     ```bash
     git clone https://github.com/yourusername/burp-sse-plugin.git
     ```
   - Open the project in your preferred Java IDE (e.g., IntelliJ IDEA, Eclipse).
   - Ensure the Burp Suite Extender API (`burp.jar`) is added to your project’s classpath.
   - Build the project to generate `BurpSSEPlugin.jar`.

2. **Load into Burp Suite**:
   - Open Burp Suite.
   - Navigate to the **Extender** tab > **Extensions** > **Add**.
   - Set the extension type to **Java** and select the compiled `BurpSSEPlugin.jar`.
   - Confirm the plugin loads successfully (check the "SSE Server" tab in Burp).

3. **Configuration File** (optional):
   - The plugin creates `sse_scripts.json` in the same directory as the JAR file on first run.
   - Pre-populate this file with encryption/decryption scripts if desired (see [Configuration](#configuration)).

## Usage

### Starting the SSE Server
1. Go to the **SSE Server** tab in Burp Suite.
2. Set the desired port (default: `8081`) in the "Port" field.
3. Click **Start Server** to launch the embedded HTTP server.
   - The server handles `/sse`, `/input`, and `/result` endpoints for real-time communication.

### Managing Scripts
1. In the **SSE Server** tab, use the "Encryption Scripts" and "Decryption Scripts" lists to view existing scripts.
2. Add a new script:
   - Enter a **Script Name**.
   - Write the script content in the text editor (JavaScript format).
   - Click **Add** (or **Update** if modifying an existing script).
3. Delete a script by selecting it and clicking **Delete**.
4. Scripts are saved to `sse_scripts.json` automatically.

**Script Example**:
```javascript
// Encryption script
function encrypt(input) {
    return btoa(input); // Base64 encode
}
this.result(msg, encrypt(msg.input));
```

```javascript
// Decryption script
function decrypt(input) {
    return atob(input); // Base64 decode
}
this.result(msg, decrypt(msg.input));
```

### Applying Encryption
1. In the **Repeater** or **Proxy** tab, right-click on a request.
2. Select **Apply Encrypt Script** > [Script Name] from the context menu.
3. The selected text will be wrapped in `[[scriptName:selectedText]]` and processed by the SSE server when sent.

### Adding Decryption Rules
1. Right-click on a request/response in any editor/viewer.
2. Choose **Add Decrypt Rule**.
3. In the dialog:
   - View the message content (read-only).
   - Adjust the regex pattern (auto-generated based on selection).
   - Select a decryption script from the dropdown.
   - Click **OK** to save the rule.
4. Rules appear in the decryption table in the **SSE Server** tab.

### Viewing Decrypted Data
- When a request/response matches a decryption rule, a **Decrypted** tab appears in the message editor.
- The tab displays the decrypted content in real-time (processed asynchronously).

### Exporting TamperMonkey Script
- Click **TamperMonkey Script** in the GUI to download `script.js` for client-side testing.

## Configuration

The plugin stores scripts in `sse_scripts.json`. Example structure:
```json
{
  "encrypt_scripts": [
    {"name": "base64_enc", "content": "function encrypt(input) { return btoa(input); } this.result(msg, encrypt(msg.input));"}
  ],
  "decrypt_scripts": [
    {"name": "base64_dec", "content": "function decrypt(input) { return atob(input); } this.result(msg, decrypt(msg.input));"}
  ]
}
```

## Endpoints

- **/sse**: Streams SSE messages for real-time updates.
- **/input**: Accepts POST requests with JSON containing `input` and `script` for processing.
- **/result**: Receives processing results via POST requests.

## Troubleshooting

- **Server Won’t Start**: Check port availability (`netstat -an | grep 8081`) and firewall settings.
- **Scripts Not Loading**: Verify `sse_scripts.json` is in the same directory as the JAR and is valid JSON.
- **Decryption Fails**: Ensure regex patterns are correct and scripts return valid output. Check Burp’s **Output** tab for errors.

## Contributing

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/new-feature`).
3. Commit changes (`git commit -m "Add new feature"`).
4. Push to the branch (`git push origin feature/new-feature`).
5. Open a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with the Burp Suite Extender API.
- Inspired by the need for flexible, real-time HTTP message processing in security testing.
