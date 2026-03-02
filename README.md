# 🔐 Secure Password Manager

A modern, secure password manager built with Tauri, React, and TypeScript that prioritizes security, usability, and privacy.

## ✨ Features

### 🛡️ Security Features

#### **Military-Grade Encryption**
- **AES-GCM 256-bit encryption** for vault storage
- **Argon2id key derivation** with configurable parameters
- **Salt-based encryption** for enhanced security
- **Atomic file operations** to prevent data corruption

#### **Breach Detection**
- **HaveIBeenPwned API integration** for real-time breach checking
- **k-Anonymity model** - your passwords never leave your device
- **SHA-1 hashing** with privacy-preserving prefix queries
- **Local caching** to minimize API calls
- **Automatic scanning** of all stored passwords

#### **Password Security Analysis**
- **Real-time strength evaluation** with detailed scoring
- **Weak password detection** (< 50% strength score)
- **Reused password identification** across services
- **Old password tracking** with age-based warnings
- **Comprehensive security dashboard** with visual indicators

#### **Master Password Protection**
- **Strong validation requirements**:
  - Minimum 8 characters, maximum 128 characters
  - Must contain uppercase, lowercase, digits, and special characters
- **Secure session management** with auto-lock functionality
- **Memory protection** for sensitive data

#### **Two-Factor Authentication (TOTP)**
- **RFC 6238 compliant** TOTP implementation
- **QR code generation** for easy setup with authenticator apps
- **6-digit time-based codes** with 30-second intervals
- **Secret key backup** for account recovery
- **Multi-device support** via standard TOTP protocol
- **Integrated verification** before enabling 2FA

### 🎯 User Interface Features

#### **First-Time Setup Wizard**
- **Guided onboarding** for new users
- **Master password creation** with real-time strength validation
- **Security recommendations** and best practices
- **Optional TOTP setup** during initialization
- **Smooth transition** to main application

#### **Modern Design**
- **Dark theme** with professional styling
- **Responsive layout** optimized for desktop use
- **Intuitive navigation** with clear visual hierarchy
- **Accessibility features** for better usability
- **Toast notifications** for user feedback and confirmations

#### **Password Management**
- **Add/Edit/Delete** password entries
- **Secure search** across services and usernames
- **URL management** with clickable links
- **Notes field** for additional information
- **Organized display** with service grouping

#### **Smart Clipboard Integration**
- **Dedicated clipboard service** with Tauri integration
- **Intelligent copy operations** for usernames and passwords
- **Auto-clear functionality** after configurable timeout
- **Secure clipboard handling** for sensitive data
- **Cross-platform support** via Tauri clipboard plugin

#### **Advanced Password Generator**
- **Customizable length** (4-128 characters)
- **Character set options**:
  - Uppercase letters (A-Z)
  - Lowercase letters (a-z)
  - Numbers (0-9)
  - Special symbols (!@#$%^&*)
- **Similar character exclusion** option
- **Real-time strength preview**
- **One-click generation** and copying

### 🔧 Technical Features

#### **Cross-Platform Desktop App**
- **Tauri framework** for native performance
- **Rust backend** for security and speed
- **React frontend** with TypeScript
- **Native OS integration**

#### **Browser Extension Integration**
- **Chrome & Firefox support** with native messaging
- **Auto-fill detection** for login forms
- **Context-aware credential matching** by domain
- **Seamless desktop app communication** via native messaging protocol
- **Password generation** directly in browser
- **Form detection** with intelligent field mapping
- **Security features**: rate limiting, origin validation, session management
- **Complete installation guide** in `BROWSER_EXTENSION_GUIDE.md`

#### **Data Management**
- **Local storage** - your data never leaves your device
- **Encrypted vault file** (vault.enc)
- **Atomic operations** to prevent corruption
- **Backup-friendly** single file storage

#### **Performance Optimizations**
- **Efficient caching** for breach detection
- **Lazy loading** for large password collections
- **Optimized rendering** with React best practices
- **Memory management** for sensitive operations

## 🚀 Getting Started

### Platform Support

✅ **Windows** - Full support with DPAPI for secure storage  
✅ **Linux** - Full support with system keyring (GNOME Keyring, KWallet)  
✅ **macOS** - Full support with macOS Keychain  

### Prerequisites
- Node.js (v16 or higher)
- Rust (latest stable)
- npm or yarn package manager
- **Linux only**: libdbus-1-dev (for keyring support)
  ```bash
  # Debian/Ubuntu
  sudo apt-get install libdbus-1-dev pkg-config
  
  # Fedora/RHEL
  sudo dnf install dbus-devel
  
  # Arch Linux
  sudo pacman -S dbus
  ```

### Installation

#### Desktop Application

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd SecurePasswordManager
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Run in development mode**
   ```bash
   npm run tauri dev
   ```

4. **Build for production**
   ```bash
   npm run tauri build
   ```

#### Jenkins CI (Linux)

This repository includes a Linux-first Jenkins pipeline at `Jenkinsfile`.

What it runs on each update:

- `npm ci`
- `npm run build`
- `cargo check --manifest-path src-tauri/Cargo.toml --all-targets`
- `cargo build --release --manifest-path src-tauri/Cargo.toml`
- `npm run tauri:build:linux` (AppImage)
- `npm run legal:bundle`

Artifacts archived by Jenkins:

- `dist/`
- `licenses/`
- `src-tauri/target/release/SecurePasswordManager`
- `src-tauri/target/release/bundle/**` (AppImage/deb/rpm if present)

Recommended Jenkins setup:

1. Create a **Multibranch Pipeline** job and point it to this repository.
2. Enable webhook from your Git provider for push/PR events.
3. Keep SCM polling as fallback (already defined in `Jenkinsfile`).
4. Use a Linux build agent with required system packages installed:

   ```bash
   # Debian/Ubuntu example for Tauri Linux builds
   sudo apt-get update
   sudo apt-get install -y \
     build-essential curl wget file pkg-config libssl-dev \
     libgtk-3-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev \
     librsvg2-dev patchelf libdbus-1-dev
   ```

#### Browser Extension (Optional)

##### Windows

1. **Build the native messaging host**
   ```bash
   npm run build:host
   ```
   This builds the Rust binary and syncs it to `native-host-bin/`

2. **Install the native messaging host**
   - Follow the detailed instructions in `BROWSER_EXTENSION_GUIDE.md`
   - The PowerShell script auto-installs to Chrome's native messaging directory
   - Update the executable path in the native messaging manifest if needed

##### Linux

1. **Build the native messaging host**
   ```bash
   npm run build:host:linux
   # Or for specific browser:
   npm run build:host:linux:brave
   npm run sync-host:linux:chrome
   npm run sync-host:linux:firefox
   ```
   This builds the Rust binary and installs manifests for Chrome/Brave/Firefox

2. **Brave Flatpak note (important)**
   - If you use Flatpak Brave (`com.brave.Browser`), the sync script configures a wrapper and required Flatpak permission automatically.
   - Re-run `npm run sync-host:linux:brave` after extension ID changes.

3. **Manual installation** (if needed)
   ```bash
   # Chrome
   mkdir -p ~/.config/google-chrome/NativeMessagingHosts
   cp browser-extension/native-messaging-host/com.passwordmanager.native.linux.json \
      ~/.config/google-chrome/NativeMessagingHosts/com.passwordmanager.native.json
   
   # Firefox
   mkdir -p ~/.mozilla/native-messaging-hosts
   cp browser-extension/native-messaging-host/com.passwordmanager.native.linux.json \
      ~/.mozilla/native-messaging-hosts/com.passwordmanager.native.json
   ```

4. **Update the manifest paths**
   - Edit the copied manifest file
   - Replace `/home/YOUR_USERNAME/SecurePasswordManager` with your actual path
   - Replace `YOUR_EXTENSION_ID` with your actual extension ID

##### Load the Extension

**Chrome/Chromium:**
- Go to `chrome://extensions/`
- Enable "Developer mode"
- Click "Load unpacked"
- Select the `browser-extension/` directory

**Firefox:**
- Go to `about:debugging#/runtime/this-firefox`
- Click "Load Temporary Add-on"
- Select `browser-extension/manifest.json`

##### Testing

**Testing**
   - See `TESTING_GUIDE.md` for comprehensive test scenarios
   - Preview components available in `browser-extension/test/`

## 🔒 Security Architecture

### Platform-Specific Secure Storage

**Windows:**
- Uses **DPAPI (Data Protection API)** for encrypting sensitive data
- TOTP secrets and device unlock keys protected by user's Windows credentials
- Automatic encryption/decryption without user intervention

**Linux:**
- Uses **system keyring** (GNOME Keyring, KWallet, or compatible)
- Integrates with desktop environment's secret storage
- Requires keyring daemon to be running

**macOS:**
- Uses **macOS Keychain** for secure storage
- Native integration with system security
- Touch ID compatible (if supported by keyring crate)

### Encryption Process
1. **Master password** is processed through Argon2id key derivation
2. **Derived key** is used for AES-GCM encryption
3. **Salt and nonce** are generated for each encryption operation
4. **Encrypted data** is stored in vault.enc file

### Privacy Protection
- **No telemetry** or data collection
- **Offline-first** design
- **Local-only** password storage
- **Privacy-preserving** breach checking

### Security Best Practices
- **Input validation** for all user data
- **Memory clearing** for sensitive operations
- **Error handling** without information leakage
- **Secure random generation** for cryptographic operations

## 📊 Security Dashboard

The integrated security analysis provides:

- **Overall security score** (0-100%)
- **Issue categorization**:
  - 🔴 **Critical**: Breached passwords
  - 🟠 **High**: Weak or reused passwords
  - 🟡 **Medium**: Old passwords (1-2 years)
  - 🟢 **Low**: Minor recommendations

- **Detailed recommendations** for each issue
- **Real-time updates** as you modify passwords
- **Visual progress tracking** for security improvements

## 🛠️ Technology Stack

### Frontend
- **React 19** with TypeScript
- **Tailwind CSS 4** for styling
- **Vite 7** for build tooling
- **React Icons** for UI icons
- **Modern ES modules**

### Backend
- **Rust** with Tauri 2.9 framework
- **Tokio** for async operations
- **Serde** for serialization
- **Ring/RustCrypto** for cryptography
- **Tauri Plugins**: dialog, global-shortcut, opener

### Security Libraries
- **Web Crypto API** for client-side hashing
- **Argon2** for key derivation
- **AES-GCM** for authenticated encryption
- **Secure random** for salt/nonce generation
- **TOTP (RFC 6238)** for two-factor authentication
- **Platform-specific secure storage**:
  - Windows: DPAPI (winapi crate)
  - Linux/macOS: System keyring (keyring crate)

### Browser Extension
- **Chrome Extension Manifest V3**
- **Native Messaging Protocol** for desktop communication
- **Content Scripts** for form detection
- **Service Worker** for background operations

## 🔐 File Structure

```
src/
├── components/                    # React components
│   ├── SecurityAnalysis.tsx       # Security dashboard & breach detection
│   ├── PasswordForm.tsx           # Add/edit password entries
│   ├── PasswordList.tsx           # Password display & management
│   ├── PasswordGenerator.tsx      # Password generation tool
│   ├── UnlockForm.tsx            # Master password entry
│   ├── ConfirmDialog.tsx         # Confirmation dialogs
│   ├── SetupWizard.tsx           # First-time setup wizard
│   ├── TOTPSetup.tsx             # Two-factor authentication setup
│   └── NotificationSystem.tsx    # Toast notifications
├── services/
│   └── clipboardService.ts       # Clipboard operations
├── utils/
│   ├── passwordAnalyzer.ts       # Password strength analysis
│   ├── passwordStrength.ts       # Strength calculation utilities
│   ├── breachChecker.ts          # HaveIBeenPwned integration
│   └── tauriEnv.ts              # Tauri environment detection
├── types.ts                      # TypeScript definitions
└── App.tsx                       # Main application

src-tauri/
├── src/
│   ├── lib.rs                    # Core Rust logic & Tauri commands
│   └── main.rs                   # Application entry point
├── Cargo.toml                    # Rust dependencies
├── tauri.conf.json              # Tauri configuration
└── capabilities/                 # Permission configurations

browser-extension/
├── manifest.json                 # Extension manifest (Chrome/Firefox)
├── background.js                 # Service worker & native messaging
├── content.js                    # Content script for form detection
├── injected.js                   # Page-level script injection
├── popup.html/js                 # Extension popup UI
├── native-messaging-host/        # Native messaging configuration
│   └── com.passwordmanager.native.json
├── test/                         # Preview & test pages
│   ├── credential_picker_preview.html
│   └── password_dialog_preview.html
└── icons/                        # Extension icons

native-host-bin/                  # Compiled native messaging host
├── SecurePasswordManager.exe     # Windows binary
└── (platform-specific binaries)

tools/
├── sync-host.ps1                # Windows: PowerShell build script
└── sync-host.sh                 # Linux/macOS: Bash build script

.gitignore                        # Git ignore rules (security-focused)
BROWSER_EXTENSION_GUIDE.md        # Browser extension setup guide
TESTING_GUIDE.md                  # Testing documentation
README.md                         # This file
```

## 🌐 Cross-Platform Notes

### Secure Storage Differences

**Windows (DPAPI)**
- Transparent encryption tied to user account
- Data persists across application restarts
- Backup: Export device.key file before Windows reinstall

**Linux (Keyring)**
- Requires keyring daemon (usually running on desktop environments)
- May prompt for keyring password on first access
- Headless systems: May need alternative configuration

**macOS (Keychain)**
- Native integration with system security
- May require keychain access permissions
- Touch ID support possible

### Browser Extension Compatibility

| Feature | Windows | Linux | macOS |
|---------|---------|-------|-------|
| Chrome Extension | ✅ | ✅ | ✅ |
| Firefox Extension | ✅ | ✅ | ✅ |
| Native Messaging | ✅ | ✅ | ✅ |
| Auto-fill | ✅ | ✅ | ✅ |
| Form Detection | ✅ | ✅ | ✅ |

## 📚 Additional Documentation

- **[BROWSER_EXTENSION_GUIDE.md](BROWSER_EXTENSION_GUIDE.md)** - Complete browser extension setup and configuration
- **[TESTING_GUIDE.md](TESTING_GUIDE.md)** - Comprehensive testing scenarios and procedures
- **[browser-extension/NATIVE_MESSAGING_DEBUG.md](browser-extension/NATIVE_MESSAGING_DEBUG.md)** - Native messaging debugging guide
- **[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)** - Open-source dependency notices and attribution summary
- **[EULA.md](EULA.md)** - End-user license agreement template for commercial distribution
- **`Jenkinsfile`** - Linux CI pipeline for automatic build and artifact generation
- **`npm run legal:bundle`** - Generates a `licenses/` folder with third-party license texts and snapshot metadata

## 🤝 Contributing

This password manager demonstrates enterprise-level security practices and is suitable for:
- **Cybersecurity professionals** learning secure development
- **Security audits** and code reviews
- **Educational purposes** for cryptography implementation
- **Portfolio projects** showcasing security expertise

## 📄 License

This repository currently includes:

- `EULA.md` for proprietary/commercial distribution terms (template; customize before release)
- `THIRD_PARTY_NOTICES.md` for open-source attribution and license obligations

If you distribute builds commercially, ensure your finalized EULA and third-party notices are included with each release.

## ⚠️ Security Notice

This password manager implements industry-standard security practices including:
- End-to-end encryption
- Zero-knowledge architecture
- Privacy-preserving breach detection
- Secure key derivation
- Memory protection

Always keep your master password secure and create regular backups of your vault.enc file.

---

**Built with security in mind. Your passwords, your control.**
