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

### 🎯 User Interface Features

#### **Modern Design**
- **Dark theme** with professional styling
- **Responsive layout** optimized for desktop use
- **Intuitive navigation** with clear visual hierarchy
- **Accessibility features** for better usability

#### **Password Management**
- **Add/Edit/Delete** password entries
- **Secure search** across services and usernames
- **URL management** with clickable links
- **Notes field** for additional information
- **Organized display** with service grouping

#### **Smart Clipboard Integration**
- **Intelligent copy operations** for usernames and passwords
- **Background monitoring** for seamless workflow
- **Auto-type functionality** for password entry
- **Temporary clipboard clearing** for security

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

### Prerequisites
- Node.js (v16 or higher)
- Rust (latest stable)
- npm or yarn package manager

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd PasswordManager
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Install Tauri CLI**
   ```bash
   npm install -g @tauri-apps/cli
   ```

4. **Run in development mode**
   ```bash
   npm run tauri dev
   ```

5. **Build for production**
   ```bash
   npm run tauri build
   ```

## 🔒 Security Architecture

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
- **React 18** with TypeScript
- **Tailwind CSS** for styling
- **Vite** for build tooling
- **Modern ES modules**

### Backend
- **Rust** with Tauri framework
- **Tokio** for async operations
- **Serde** for serialization
- **Ring/RustCrypto** for cryptography

### Security Libraries
- **Web Crypto API** for client-side hashing
- **Argon2** for key derivation
- **AES-GCM** for authenticated encryption
- **Secure random** for salt/nonce generation

## 🔐 File Structure

```
src/
├── components/           # React components
│   ├── SecurityAnalysis.tsx    # Security dashboard
│   ├── PasswordForm.tsx        # Add/edit passwords
│   ├── PasswordList.tsx        # Password display
│   ├── PasswordGenerator.tsx   # Password generation
│   ├── UnlockForm.tsx         # Master password entry
│   └── ConfirmDialog.tsx      # Confirmation dialogs
├── utils/
│   └── passwordAnalyzer.ts    # Password strength analysis
├── types.ts             # TypeScript definitions
└── App.tsx             # Main application

src-tauri/
├── src/
│   ├── lib.rs          # Core Rust logic
│   └── main.rs         # Application entry
└── vault.enc           # Encrypted password vault
```

## 🤝 Contributing

This password manager demonstrates enterprise-level security practices and is suitable for:
- **Cybersecurity professionals** learning secure development
- **Security audits** and code reviews
- **Educational purposes** for cryptography implementation
- **Portfolio projects** showcasing security expertise

## 📄 License

This project is for educational and professional development purposes.

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
