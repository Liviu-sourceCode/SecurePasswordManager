# Password Manager Browser Extension

This browser extension provides seamless integration between your Password Manager application and web browsers, enabling automatic form detection, credential auto-fill, and password generation.

## Features

- 🔍 **Automatic Form Detection**: Detects login forms on websites
- 🔐 **Auto-Fill Credentials**: Fill saved credentials with one click
- 🎲 **Password Generation**: Generate secure passwords with customizable options
- 💾 **Save Credentials**: Automatically prompt to save new credentials
- 🔒 **Secure Communication**: Uses native messaging for secure communication with the desktop app

## Installation

### 1. Build the Tauri Application

First, make sure your Password Manager Tauri application is built:

```bash
cd src-tauri
cargo build
```

### 2. Install Native Messaging Host

The browser needs to know how to communicate with your Tauri app. You need to register the native messaging host:

#### For Chrome/Chromium:

1. Copy the native messaging host manifest to the appropriate location:
   - **Windows**: `%LOCALAPPDATA%\Google\Chrome\User Data\NativeMessagingHosts\`
   - **macOS**: `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`
   - **Linux**: `~/.config/google-chrome/NativeMessagingHosts/`

2. Update the manifest file `com.passwordmanager.native.json`:
   - Replace `EXTENSION_ID_PLACEHOLDER` with your actual extension ID
   - Update the `path` to point to your built Tauri executable

#### For Firefox:

1. Copy the manifest to:
   - **Windows**: `%LOCALAPPDATA%\Mozilla\NativeMessagingHosts\`
   - **macOS**: `~/Library/Application Support/Mozilla/NativeMessagingHosts/`
   - **Linux**: `~/.mozilla/native-messaging-hosts/`

### 3. Load the Extension

#### Chrome/Chromium:

1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode" in the top right
3. Click "Load unpacked"
4. Select the `browser-extension` folder
5. Note the extension ID that appears

#### Firefox:

1. Open Firefox and go to `about:debugging`
2. Click "This Firefox"
3. Click "Load Temporary Add-on"
4. Select the `manifest.json` file in the `browser-extension` folder

### 4. Update Native Messaging Host

After loading the extension and getting the extension ID:

1. Edit `native-messaging-host/com.passwordmanager.native.json`
2. Replace `EXTENSION_ID_PLACEHOLDER` with the actual extension ID
3. Copy the updated manifest to the native messaging hosts directory

## Usage

### Auto-Fill Credentials

1. Navigate to a website with a login form
2. Click the Password Manager extension icon in the toolbar
3. Select the credentials you want to use
4. The form will be automatically filled

### Generate Passwords

1. Click the Password Manager extension icon
2. In the "Password Generator" section, configure your preferences:
   - Set the desired length (8-128 characters)
   - Choose character types (uppercase, lowercase, numbers, symbols)
3. Click "Generate Password"
4. Click the generated password to copy it to clipboard

### Save New Credentials

1. Fill out a login form manually
2. Submit the form
3. The extension will automatically prompt to save the credentials
4. Confirm to save them to your Password Manager

## Troubleshooting

### Extension Not Connecting

1. **Check if the Tauri app is running**: The Password Manager desktop application must be running for the extension to work.

2. **Verify native messaging host installation**: Make sure the manifest file is in the correct location and has the right extension ID.

3. **Check file paths**: Ensure the `path` in the native messaging manifest points to the correct executable.

4. **Permissions**: On some systems, you may need to make the executable file executable:
   ```bash
   chmod +x /path/to/password-manager
   ```

### Forms Not Being Detected

1. **Refresh the page**: Sometimes forms loaded dynamically need a page refresh.

2. **Check form structure**: The extension looks for standard HTML form elements. Some custom forms may not be detected.

3. **Manual trigger**: Use the extension popup to manually fill credentials.

### Native Messaging Errors

Check the browser console (F12) and look for native messaging errors. Common issues:

- **Host not found**: The native messaging host manifest is not installed correctly
- **Permission denied**: The executable doesn't have the right permissions
- **Path not found**: The path in the manifest is incorrect

## Development

### File Structure

```
browser-extension/
├── manifest.json           # Extension manifest
├── background.js          # Service worker for native messaging
├── content.js            # Content script for form detection
├── popup.html            # Extension popup UI
├── popup.js              # Popup functionality
├── icons/                # Extension icons
└── native-messaging-host/
    └── com.passwordmanager.native.json  # Native messaging manifest
```

### Testing

1. Load the extension in developer mode
2. Open the browser console to see debug messages
3. Test on various websites with different form structures
4. Verify native messaging communication in the background script console

## Security Notes

- The extension only communicates with the local Password Manager application.
- Host → extension passwords are encrypted using AES‑256‑GCM with a random nonce per request. The content and popup scripts decrypt using WebCrypto (`crypto.subtle`).
- Internal extension messaging no longer uses custom XOR schemes. The master password prompt sends plaintext only within the extension’s isolated messaging channel (not accessible to page scripts).
- No credentials are stored in the browser extension itself; the master password is cached in memory briefly for convenience and then cleared.
- The extension validates the origin of all requests.

## Browser Compatibility

- **Chrome/Chromium**: Manifest V3 (recommended)
- **Firefox**: Compatible with WebExtensions API
- **Edge**: Compatible with Chromium-based Edge

## License

This extension is part of the Password Manager project and follows the same license terms.