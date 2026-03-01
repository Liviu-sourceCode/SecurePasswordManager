use chacha20poly1305::{aead::{Aead, Payload}, XChaCha20Poly1305, XNonce};
use chacha20poly1305::KeyInit;
use argon2::{Argon2, Params, Algorithm, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use enigo::{Enigo, Key as EnigoKey, Keyboard, Settings};
use zeroize::Zeroize;
use rdev::{listen, Event, EventType, Key as RdevKey};

use rand::rngs::OsRng;
use rand::RngCore;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Write, Read},

    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};

use tauri::State;
use tauri::Manager;
use tauri::Emitter;
use thiserror::Error;
use tokio::time::sleep;
use tauri::AppHandle;
use arboard::Clipboard;
use std::sync::Arc;
use tokio::sync::RwLock;

use url;
use fs2::FileExt;

// Custom error types for better error handling
#[derive(Error, Debug)]
pub enum PasswordManagerError {
    #[error("Vault is locked")]
    VaultLocked,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Encryption failed")]
    EncryptionError,
    #[error("Decryption failed")]
    DecryptionError,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Mutex lock error")]
    MutexError,
    #[error("TOTP error: {0}")]
    TotpError(String),
    #[error("System error: {0}")]
    SystemError(String),
    #[error("Memory protection error")]
    MemoryProtectionError,
    #[error("Session timeout")]
    SessionTimeout,
}

// Sanitize error messages to prevent information leakage
fn sanitize_error(error: &str) -> String {
    // Map specific internal errors to generic user-friendly messages
    if error.contains("No such file or directory") || error.contains("cannot find the file") {
        return "Vault file not found. Please create a new vault.".to_string();
    }
    if error.contains("Permission denied") || error.contains("Access is denied") {
        return "Access denied. Please check file permissions.".to_string();
    }
    if error.contains("already exists") {
        return "Vault already exists.".to_string();
    }
    if error.contains("corrupted") || error.contains("invalid") || error.contains("malformed") {
        return "Vault data is corrupted. Please restore from backup.".to_string();
    }
    if error.contains("network") || error.contains("connection") || error.contains("timeout") {
        return "Network error occurred. Please try again.".to_string();
    }
    if error.contains("disk") || error.contains("space") || error.contains("storage") {
        return "Insufficient storage space.".to_string();
    }
    if error.contains("lock") || error.contains("busy") {
        return "Resource is currently in use. Please try again.".to_string();
    }
    if error.contains("os error 5") {
        return "Access denied by the operating system. Check file permissions.".to_string();
    }
    if error.contains("os error 32") {
        return "File is being used by another process. Please close other applications.".to_string();
    }
    
    // For any other errors, return a generic message with a log reference if needed (simplified here)
    format!("An unexpected error occurred: {}. Please try again.", error)
}

// New imports for TOTP and DPAPI
use totp_rs::{Algorithm as TOTPAlgorithm, TOTP, Secret};
// Replace windows crate DPAPI imports with winapi
use winapi::um::dpapi::{CryptProtectData, CryptUnprotectData};
use winapi::um::wincrypt::DATA_BLOB;
use winapi::um::winbase::LocalFree;
use winapi::shared::minwindef::HLOCAL;
#[cfg(windows)]
use winapi::um::processenv::GetStdHandle;
#[cfg(windows)]
use winapi::um::fileapi::GetFileType;
#[cfg(windows)]
use winapi::um::winbase::{STD_INPUT_HANDLE, FILE_TYPE_PIPE};
#[cfg(windows)]
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
// Removed unused system identifiers imports after stabilizing DPAPI usage
use winapi::um::memoryapi::VirtualLock;
use winapi::shared::minwindef::{BOOL, LPVOID};
use winapi::shared::basetsd::SIZE_T;

// Removed unused OsString imports


#[cfg(unix)]
use mlock::{mlock, munlock};

// Error handling
#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Vault is not unlocked")]
    NotUnlocked,
    #[error("Failed to encrypt data")]
    EncryptionError,
    #[error("Failed to decrypt data")]
    DecryptionError,
    #[error("Invalid master password")]
    InvalidPassword,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Insufficient disk space")]
    InsufficientDiskSpace,
    #[error("File is locked by another process")]
    FileLocked,
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Vault file is corrupted")]
    Corrupted,
    #[error("Vault file not found")]
    NotFound,
}

// Input validation constants
const MAX_SERVICE_LENGTH: usize = 100;
const MAX_USERNAME_LENGTH: usize = 100;
const MAX_PASSWORD_LENGTH: usize = 500;
const MAX_URL_LENGTH: usize = 2000;
const MAX_NOTES_LENGTH: usize = 1000;
const MIN_MASTER_PASSWORD_LENGTH: usize = 8;
const MAX_MASTER_PASSWORD_LENGTH: usize = 128;

// Input validation functions
fn validate_master_password(password: &str) -> Result<(), VaultError> {
    if password.len() < MIN_MASTER_PASSWORD_LENGTH {
        return Err(VaultError::ValidationError(format!(
            "Master password must be at least {} characters long", 
            MIN_MASTER_PASSWORD_LENGTH
        )));
    }
    
    if password.len() > MAX_MASTER_PASSWORD_LENGTH {
        return Err(VaultError::ValidationError(format!(
            "Master password must not exceed {} characters", 
            MAX_MASTER_PASSWORD_LENGTH
        )));
    }
    
    // Check for at least one uppercase, one lowercase, one digit, and one special character
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    
    if !(has_upper && has_lower && has_digit && has_special) {
        return Err(VaultError::ValidationError(
            "Master password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character".to_string()
        ));
    }
    
    Ok(())
}

fn validate_password_entry(entry: &PasswordEntry) -> Result<(), VaultError> {
    // Security validation for all fields
    validate_input_security(&entry.service)?;
    validate_input_security(&entry.username)?;
    validate_input_security(&entry.password)?;
    
    if let Some(url) = &entry.url {
        validate_input_security(url)?;
    }
    
    if let Some(notes) = &entry.notes {
        validate_input_security(notes)?;
    }
    
    // Validate service name
    if entry.service.trim().is_empty() {
        return Err(VaultError::ValidationError("Service name cannot be empty".to_string()));
    }
    if entry.service.len() > MAX_SERVICE_LENGTH {
        return Err(VaultError::ValidationError(format!(
            "Service name must not exceed {} characters", 
            MAX_SERVICE_LENGTH
        )));
    }
    
    // Check for valid service name characters
    if !entry.service.chars().all(|c| c.is_alphanumeric() || " .-_".contains(c)) {
        return Err(VaultError::ValidationError(
            "Service name contains invalid characters".to_string()
        ));
    }
    
    // Validate username
    if entry.username.trim().is_empty() {
        return Err(VaultError::ValidationError("Username cannot be empty".to_string()));
    }
    if entry.username.len() > MAX_USERNAME_LENGTH {
        return Err(VaultError::ValidationError(format!(
            "Username must not exceed {} characters", 
            MAX_USERNAME_LENGTH
        )));
    }
    
    // Validate password
    if entry.password.trim().is_empty() {
        return Err(VaultError::ValidationError("Password cannot be empty".to_string()));
    }
    if entry.password.len() > MAX_PASSWORD_LENGTH {
        return Err(VaultError::ValidationError(format!(
            "Password must not exceed {} characters", 
            MAX_PASSWORD_LENGTH
        )));
    }
    
    // Validate URL (optional)
    if let Some(url) = &entry.url {
        if !url.is_empty() {
            if url.len() > MAX_URL_LENGTH {
                return Err(VaultError::ValidationError(format!(
                    "URL must not exceed {} characters", 
                    MAX_URL_LENGTH
                )));
            }
            
            // Enhanced URL validation
            validate_url(url)?;
        }
    }
    
    // Validate notes (optional)
    if let Some(notes) = &entry.notes {
        if notes.len() > MAX_NOTES_LENGTH {
            return Err(VaultError::ValidationError(format!(
                "Notes must not exceed {} characters", 
                MAX_NOTES_LENGTH
            )));
        }
    }
    
    Ok(())
}

fn validate_url(url: &str) -> Result<(), VaultError> {
    // Check for valid URL schemes
    let valid_schemes = ["http://", "https://", "ftp://", "ftps://"];
    let has_valid_scheme = valid_schemes.iter().any(|&scheme| url.starts_with(scheme));
    
    if !has_valid_scheme {
        // Allow domain-only URLs (e.g., "example.com")
        let domain_regex = regex::Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.([a-zA-Z]{2,}|[a-zA-Z]{2,}\.[a-zA-Z]{2,})(/.*)?$").unwrap();
        if !domain_regex.is_match(url) {
            return Err(VaultError::ValidationError(
                "Invalid URL format. Use http://, https://, ftp://, or domain.com format".to_string()
            ));
        }
    }
    
    // Check for suspicious URL patterns
    let suspicious_url_patterns = [
        r"(?i)javascript:",
        r"(?i)data:",
        r"(?i)vbscript:",
        r"(?i)file:",
        r"\.\.[\\/]", // Path traversal
        "[<>\"']", // HTML injection characters
    ];
    
    for pattern in &suspicious_url_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(url) {
                return Err(VaultError::ValidationError(
                    "URL contains potentially malicious content".to_string()
                ));
            }
        }
    }
    
    Ok(())
}

fn sanitize_input(input: &str) -> String {
    // Remove null bytes and control characters except newlines and tabs
    let basic_sanitized = input.chars()
        .filter(|&c| c != '\0' && (c.is_control() == false || c == '\n' || c == '\t'))
        .collect::<String>();
    
    // Remove potentially dangerous patterns
    let mut sanitized = basic_sanitized
        .replace('\u{FEFF}', "") // Remove BOM
        .replace('\u{200B}', "") // Remove zero-width space
        .replace('\u{200C}', "") // Remove zero-width non-joiner
        .replace('\u{200D}', "") // Remove zero-width joiner
        .replace('\u{2060}', ""); // Remove word joiner
    
    // Remove HTML/XML tags for XSS prevention
    sanitized = regex::Regex::new(r"<[^>]*>").unwrap().replace_all(&sanitized, "").to_string();
    
    // Remove SQL injection patterns (basic protection)
    let sql_patterns = [
        r"(?i)\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b",
        r"(?i)--",
        r"/\*.*?\*/",
        r"(?i)\b(or|and)\s+\d+\s*=\s*\d+",
        "(?i)\\b(or|and)\\s+['\"].*?['\"]",
    ];
    
    for pattern in &sql_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            sanitized = re.replace_all(&sanitized, "").to_string();
        }
    }
    
    // Remove script injection patterns
    let script_patterns = [
        r"(?i)javascript:",
        r"(?i)vbscript:",
        r"(?i)data:",
        r"(?i)on\w+\s*=",
    ];
    
    for pattern in &script_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            sanitized = re.replace_all(&sanitized, "").to_string();
        }
    }
    
    sanitized.trim().to_string()
}

fn validate_input_security(input: &str) -> Result<(), VaultError> {
    // Check for suspicious patterns that might indicate attacks
    let suspicious_patterns = [
        r"\.\.[\\/]", // Path traversal
        r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", // Control characters
        r"(?i)<script", // Script tags
        r"(?i)eval\s*\(", // Eval functions
        r"(?i)expression\s*\(", // CSS expressions
        r"(?i)import\s+", // Import statements
        r"(?i)require\s*\(", // Require calls
    ];
    
    for pattern in &suspicious_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(input) {
                return Err(VaultError::ValidationError(
                    "Input contains potentially malicious content".to_string()
                ));
            }
        }
    }
    
    // Check for excessive length that might indicate buffer overflow attempts
    if input.len() > 10000 {
        return Err(VaultError::ValidationError(
            "Input exceeds maximum allowed length".to_string()
        ));
    }
    
    Ok(())
}

// Data structures
#[derive(Serialize, Deserialize, Clone)]
pub struct PasswordEntry {
    id: String,
    service: String,
    username: String,
    password: String,
    url: Option<String>,
    notes: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
struct Argon2Params {
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    algorithm: String,
    version: String,
}

#[derive(Serialize, Deserialize)]
struct EncryptedVault {
    version: u32,
    argon2_params: Argon2Params,
    salt: String,
    nonce: String,
    data: String,
    verifier: String, // HKDF-derived key verifier
    aad: String,      // Additional authenticated data
}

#[derive(Serialize, Deserialize, Clone)]
struct TotpAccount {
    username: String,
    password: String,
    issuer: String,
    account_name: String,
}

#[derive(Serialize, Deserialize)]
struct VaultPayload {
    entries: Vec<PasswordEntry>,
    totp_account: Option<TotpAccount>,
}

// Secure key container that zeroizes on drop
#[derive(Clone)]
struct SecureKey {
    inner: [u8; 32],
}

impl SecureKey {
    fn new(bytes: [u8; 32]) -> Self {
        SecureKey { inner: bytes }
    }

    fn expose(&self) -> &[u8; 32] {
        &self.inner
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

struct VaultState {
    entries: Vec<PasswordEntry>,
    totp_account: Option<TotpAccount>,
    last_activity: Instant,
    is_locked: bool,
    session_timeout_minutes: u64,
}

struct AppState {
    vault: Mutex<VaultState>,
    master_key: Mutex<Option<SecureKey>>,
    mfa_verified_at: Mutex<Option<Instant>>,
}

#[derive(Clone)]
struct SmartClipboardState {
    is_active: bool,
    username: String,
    password: String,
    last_username_copy: Option<Instant>,
    expected_clipboard_content: String,
    interference_detected: bool,
}

struct SmartClipboardManager {
    state: Arc<RwLock<SmartClipboardState>>,
}



// GlobalKeyManager removed - not needed with direct function approach

// Replace the current VAULT_FILE constant with this
const VAULT_FILE: &str = "vault.enc";
const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(180); // 3 minutes
const MIN_FREE_SPACE_BYTES: u64 = 10 * 1024 * 1024; // 10 MB minimum free space
const CLIPBOARD_AUTO_CLEAR_AFTER: Duration = Duration::from_secs(30);

fn get_vault_path(app_handle: &AppHandle) -> Result<PathBuf, VaultError> {
    // Use app local data directory - this already includes the app identifier
    let app_data_dir = app_handle.path().app_local_data_dir()
        .map_err(|e| VaultError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
    
    // Create the app data directory if it doesn't exist
    std::fs::create_dir_all(&app_data_dir)
        .map_err(|e| VaultError::IoError(e))?;
    
    let vault_path = app_data_dir.join(VAULT_FILE);
    
    Ok(vault_path)
}

// Path helper for TOTP secret file
fn get_totp_secret_path(app_handle: &AppHandle) -> Result<PathBuf, VaultError> {
    let vault_path = get_vault_path(app_handle)?;
    let dir = vault_path.parent().unwrap_or(std::path::Path::new("."));
    Ok(dir.join("totp.secret"))
}

// Path helper for DPAPI-protected device unlock key
fn get_device_unlock_key_path(app_handle: &AppHandle) -> Result<PathBuf, VaultError> {
    let vault_path = get_vault_path(app_handle)?;
    let dir = vault_path.parent().unwrap_or(std::path::Path::new("."));
    Ok(dir.join("device.key"))
}

// Removed get_machine_id: DPAPI is used without custom entropy for stability across restarts.

// DPAPI helpers using winapi
fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>, VaultError> {
    unsafe {
        let mut in_blob = DATA_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out_blob = DATA_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let res = CryptProtectData(
            &mut in_blob,
            std::ptr::null_mut(), // Description
            std::ptr::null_mut(), // Entropy (none for stability across restarts)
            std::ptr::null_mut(), // Reserved
            std::ptr::null_mut(), // Prompt struct
            0,                    // Flags
            &mut out_blob,
        );
        if res == 0 {
            return Err(VaultError::EncryptionError);
        }
        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let mut out = Vec::with_capacity(slice.len());
        out.extend_from_slice(slice);
        LocalFree(out_blob.pbData as HLOCAL);
        Ok(out)
    }
}

fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>, VaultError> {
    unsafe {
        let mut in_blob = DATA_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out_blob = DATA_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let res = CryptUnprotectData(
            &mut in_blob,
            std::ptr::null_mut(), // Description
            std::ptr::null_mut(), // Entropy (none for stability across restarts)
            std::ptr::null_mut(), // Reserved
            std::ptr::null_mut(), // Prompt struct
            0,                    // Flags
            &mut out_blob,
        );
        if res == 0 {
            return Err(VaultError::DecryptionError);
        }
        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let mut out = Vec::with_capacity(slice.len());
        out.extend_from_slice(slice);
        LocalFree(out_blob.pbData as HLOCAL);
        Ok(out)
    }
}

// Check available disk space
fn check_disk_space(path: &PathBuf) -> Result<(), VaultError> {
    if let Some(parent) = path.parent() {
        match fs2::available_space(parent) {
            Ok(available) => {
                if available < MIN_FREE_SPACE_BYTES {
                    return Err(VaultError::InsufficientDiskSpace);
                }
            }
            Err(_) => {
                // If we can't check disk space, proceed but log warning
                eprintln!("Warning: Could not check available disk space");
            }
        }
    }
    Ok(())
}

// Create backup of existing vault
fn create_backup(vault_path: &PathBuf) -> Result<(), VaultError> {
    if vault_path.exists() {
        let backup_path = vault_path.with_extension("bak");
        fs::copy(vault_path, backup_path)?;
    }
    Ok(())
}

// Restore from backup if main vault is corrupted
fn restore_from_backup(vault_path: &PathBuf) -> Result<bool, VaultError> {
    let backup_path = vault_path.with_extension("bak");
    if backup_path.exists() {
        fs::copy(&backup_path, vault_path)?;
        return Ok(true);
    }
    Ok(false)
}
// Security constants
const ARGON2_MEMORY_COST: u32 = 65536; // 64 MB
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const VAULT_VERSION: u32 = 2;

// Helper functions for secure encryption
fn get_argon2_params() -> Argon2Params {
    Argon2Params {
        memory_cost: ARGON2_MEMORY_COST,
        time_cost: ARGON2_TIME_COST,
        parallelism: ARGON2_PARALLELISM,
        algorithm: "Argon2id".to_string(),
        version: "0x13".to_string(),
    }
}

fn derive_master_key(password: &str, salt: &[u8]) -> Result<SecureKey, VaultError> {
    let params = Params::new(
        ARGON2_MEMORY_COST,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(32),
    ).map_err(|_| VaultError::EncryptionError)?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut master_key = [0u8; 32];
    
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut master_key)
        .map_err(|_| VaultError::EncryptionError)?;
    
    // Lock the memory of the derived key buffer (best effort on Unix)
    let ptr = master_key.as_mut_ptr();
    let len = master_key.len();
    let _ = secure_memory(ptr, len);

    Ok(SecureKey::new(master_key))
}

fn derive_master_key_with_params(password: &str, salt: &[u8], params_in: &Argon2Params) -> Result<SecureKey, VaultError> {
    let params = Params::new(
        params_in.memory_cost,
        params_in.time_cost,
        params_in.parallelism,
        Some(32),
    ).map_err(|_| VaultError::EncryptionError)?;

    let algorithm = match params_in.algorithm.as_str() {
        "Argon2id" => Algorithm::Argon2id,
        "Argon2i" => Algorithm::Argon2i,
        "Argon2d" => Algorithm::Argon2d,
        _ => Algorithm::Argon2id,
    };

    let version = match params_in.version.as_str() {
        "0x13" => Version::V0x13,
        "0x10" => Version::V0x10,
        _ => Version::V0x13,
    };

    let argon2 = Argon2::new(algorithm, version, params);
    let mut master_key = [0u8; 32];

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut master_key)
        .map_err(|_| VaultError::EncryptionError)?;

    // Lock the memory of the derived key buffer (best effort on Unix)
    let ptr = master_key.as_mut_ptr();
    let len = master_key.len();
    let _ = secure_memory(ptr, len);

    Ok(SecureKey::new(master_key))
}

fn derive_keys(master_key: &SecureKey, salt: &[u8]) -> Result<(SecureKey, [u8; 32]), VaultError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master_key.expose());
    
    // Derive encryption key (32 bytes for XChaCha20)
    let mut encryption_key = [0u8; 32];
    hkdf.expand(b"encryption", &mut encryption_key)
        .map_err(|_| VaultError::EncryptionError)?;
    
    // Derive verifier (32 bytes)
    let mut verifier = [0u8; 32];
    hkdf.expand(b"verifier", &mut verifier)
        .map_err(|_| VaultError::EncryptionError)?;
    
    Ok((SecureKey::new(encryption_key), verifier))
}

fn encrypt_with_aad(data: &[u8], key: &SecureKey, aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
        .map_err(|_| VaultError::EncryptionError)?;
    
    let mut nonce_bytes = [0u8; 24]; // XChaCha20 uses 24-byte nonces
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: data, aad })
        .map_err(|_| VaultError::EncryptionError)?;
    
    Ok((ciphertext, nonce_bytes.to_vec()))
}

fn decrypt_with_aad(ciphertext: &[u8], key: &SecureKey, nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, VaultError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
        .map_err(|_| VaultError::DecryptionError)?;
    
    let nonce = XNonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| VaultError::DecryptionError)?;
    
    Ok(plaintext)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn verify_master_key(master_key: &SecureKey, salt: &[u8], stored_verifier: &[u8]) -> Result<bool, VaultError> {
    let (_, verifier) = derive_keys(master_key, salt)?;
    Ok(constant_time_eq(stored_verifier, verifier.as_ref()))
}

#[cfg(unix)]
fn secure_memory(ptr: *mut u8, len: usize) -> Result<(), PasswordManagerError> {
    unsafe {
        if mlock(ptr, len).is_err() {
            return Err(PasswordManagerError::MemoryProtectionError);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn secure_memory(ptr: *mut u8, len: usize) -> Result<(), PasswordManagerError> {
    unsafe {
        let result: BOOL = VirtualLock(ptr as LPVOID, len as SIZE_T);
        if result == 0 {
            return Err(PasswordManagerError::MemoryProtectionError);
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn secure_memory(_ptr: *mut u8, _len: usize) -> Result<(), PasswordManagerError> {
    // Memory locking not available on this platform
    Err(PasswordManagerError::MemoryProtectionError)
}

#[cfg(unix)]
fn unsecure_memory(ptr: *mut u8, len: usize) -> Result<(), PasswordManagerError> {
    unsafe {
        if munlock(ptr, len).is_err() {
            return Err(PasswordManagerError::MemoryProtectionError);
        }
    }
    Ok(())
}



// Session management functions
fn check_session_timeout(app_handle: &AppHandle, vault: &mut VaultState) -> Result<(), PasswordManagerError> {
    if !vault.is_locked {
        let elapsed = vault.last_activity.elapsed();
        let timeout_duration = Duration::from_secs(vault.session_timeout_minutes * 60);
        
        if elapsed > timeout_duration {
            vault.is_locked = true;
            println!("[DEBUG] Session timeout: Vault automatically locked after {} minutes", vault.session_timeout_minutes);
            let _ = app_handle.emit("vault_auto_locked", serde_json::json!({ "reason": "session_timeout" }));
            return Err(PasswordManagerError::SessionTimeout);
        }
    }
    Ok(())
}

fn update_activity(vault: &mut VaultState) {
    vault.last_activity = Instant::now();
}

// Helper function to safely lock mutex and handle errors
fn lock_vault_state(app_state: &AppState) -> Result<std::sync::MutexGuard<'_, VaultState>, PasswordManagerError> {
    app_state.vault.lock().map_err(|_| PasswordManagerError::MutexError)
}

fn lock_master_key(app_state: &AppState) -> Result<std::sync::MutexGuard<'_, Option<SecureKey>>, PasswordManagerError> {
    app_state.master_key.lock().map_err(|_| PasswordManagerError::MutexError)
}

fn lock_mfa_time(app_state: &AppState) -> Result<std::sync::MutexGuard<'_, Option<Instant>>, PasswordManagerError> {
    app_state.mfa_verified_at.lock().map_err(|_| PasswordManagerError::MutexError)
}

// Tauri commands





#[tauri::command]
async fn vault_exists(app_handle: AppHandle) -> Result<bool, String> {
    let vault_path = get_vault_path(&app_handle).map_err(|e| sanitize_error(&e.to_string()))?;
    let path_str = vault_path.to_string_lossy().to_string();
    let _ = write_audit_log(&app_handle, "vault_check", &format!("Checking vault path: {}", path_str));

    if vault_path.exists() {
        let _ = write_audit_log(&app_handle, "vault_check", &format!("Vault exists at: {}", path_str));
        return Ok(true);
    }

    // Attempt legacy auto-migration from common dev locations
    if let Ok(current_dir) = std::env::current_dir() {
        let mut candidates: Vec<std::path::PathBuf> = Vec::new();
        // 1) Current working directory (often src-tauri during dev)
        candidates.push(current_dir.join(VAULT_FILE));
        // 2) Project root directory (parent of src-tauri)
        if let Some(parent) = current_dir.parent() {
            candidates.push(parent.join(VAULT_FILE));
        }
        // 3) One level up (handles nested repos)
        if let Some(grand) = current_dir.parent().and_then(|p| p.parent()) {
            candidates.push(grand.join(VAULT_FILE));
        }

        for legacy_path in candidates.into_iter() {
            let legacy_str = legacy_path.to_string_lossy().to_string();
            let _ = write_audit_log(&app_handle, "vault_migration_check", &format!("Legacy path considered: {} (exists={})", legacy_str, legacy_path.exists()));
            if legacy_path.exists() {
                if let Some(parent) = vault_path.parent() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        let _ = write_audit_log(&app_handle, "vault_migration_error", &format!("Failed to create target dir for {}: {}", path_str, e));
                        return Err(e.to_string());
                    }
                }
                if let Err(e) = std::fs::copy(&legacy_path, &vault_path) {
                    let _ = write_audit_log(&app_handle, "vault_migration_error", &format!("Failed to migrate {} -> {}: {}", legacy_str, path_str, e));
                    return Err(e.to_string());
                }
                let _ = write_audit_log(&app_handle, "vault_migrated", &format!("Migrated legacy vault from {} to {}", legacy_str, path_str));
                return Ok(true);
            }
        }
    }

    let _ = write_audit_log(&app_handle, "vault_check", &format!("Vault not found at: {}", path_str));
    Ok(false)
}


#[tauri::command]
async fn create_vault(password: String, app_state: State<'_, AppState>, app_handle: AppHandle) -> Result<Vec<PasswordEntry>, String> {
    println!("[DEBUG] Starting create_vault");
    // Always validate master password for new vault creation
    validate_master_password(&password).map_err(|e| e.to_string())?;
    println!("[DEBUG] Password validated");
    
    // Get the vault path (creates directory if needed)
    let vault_path = get_vault_path(&app_handle).map_err(|e| sanitize_error(&e.to_string()))?;
    let path_str = vault_path.to_string_lossy().to_string();
    let _ = write_audit_log(&app_handle, "vault_create_path", &format!("Target path: {}", path_str));
    println!("[DEBUG] Vault path: {:?}", vault_path);
    
    // Safety guard: never overwrite an existing vault
    if vault_path.exists() {
        let _ = write_audit_log(&app_handle, "vault_create_error", &format!("Vault already exists at {}", path_str));
        println!("[DEBUG] Vault already exists, aborting");
        return Err("Vault already exists. Please unlock your vault.".to_string());
    }
    println!("[DEBUG] Vault does not exist, proceeding");
    
    // Generate 32 bytes of salt for enhanced security
    let mut salt_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut salt_bytes);
    println!("[DEBUG] Salt generated");
    
    // Derive master key using Argon2id
    let master_key = derive_master_key(&password, &salt_bytes).map_err(|e| e.to_string())?;
    println!("[DEBUG] Master key derived");
    
    // Derive encryption key and verifier using HKDF
    let (encryption_key, verifier) = derive_keys(&master_key, &salt_bytes).map_err(|e| e.to_string())?;
    println!("[DEBUG] Encryption key and verifier derived");
    
    // Store master key securely
    *lock_master_key(&app_state).map_err(|e| e.to_string())? = Some(master_key);
    println!("[DEBUG] Master key stored in state");

    let initial_entries: Vec<PasswordEntry> = Vec::new();
    let payload = VaultPayload { entries: initial_entries.clone(), totp_account: None };
    let vault_data = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
    println!("[DEBUG] Vault payload serialized");
    
    // Generate AAD (Additional Authenticated Data)
    let aad = format!("vault_v{}_created_{}", VAULT_VERSION, chrono::Utc::now().timestamp());
    let aad_bytes = aad.as_bytes();
    println!("[DEBUG] AAD generated");
    
    let (encrypted_data, nonce) = encrypt_with_aad(&vault_data, &encryption_key, aad_bytes).map_err(|e| e.to_string())?;
    println!("[DEBUG] Vault data encrypted");

    let encrypted_vault = EncryptedVault {
        version: VAULT_VERSION,
        argon2_params: get_argon2_params(),
        salt: BASE64.encode(&salt_bytes),
        nonce: BASE64.encode(&nonce),
        data: BASE64.encode(&encrypted_data),
        verifier: BASE64.encode(&verifier),
        aad: BASE64.encode(aad_bytes),
    };
    
    let json = serde_json::to_string(&encrypted_vault).map_err(|e| e.to_string())?;
    fs::write(&vault_path, json).map_err(|e| e.to_string())?;
    println!("[DEBUG] Vault created successfully at {:?}", vault_path);
    
    let mut vault = lock_vault_state(&app_state).map_err(|e| e.to_string())?;
    vault.entries = initial_entries;
    vault.totp_account = None;
    update_activity(&mut vault);
    vault.is_locked = false;
    println!("[DEBUG] Vault unlocked and state updated");
    
    // Log vault creation (audit trail)
    if let Err(err) = write_audit_log(&app_handle, "vault_create", "Vault created") {
        eprintln!("AUDIT WRITE ERROR: {}", err);
    }
    println!("[DEBUG] Audit log written");
    
    Ok(Vec::new())
}

#[tauri::command]
async fn unlock_vault(password: String, app_state: State<'_, AppState>, app_handle: AppHandle) -> Result<Vec<PasswordEntry>, String> {
    eprintln!("=== UNLOCK_VAULT START ===");
    let start_time = std::time::Instant::now();
    
    let vault_path = get_vault_path(&app_handle).map_err(|e| sanitize_error(&e.to_string()))?;
    eprintln!("UNLOCK: Got vault path in {:?}", start_time.elapsed());
    
    // For unlocking, the vault file must exist
    if !vault_path.exists() {
        eprintln!("UNLOCK: Vault file does not exist");
        return Err("Vault not found. Please create a vault first.".to_string());
    }
    eprintln!("UNLOCK: Vault file exists, proceeding to read in {:?}", start_time.elapsed());

    // Early MFA enforcement to avoid expensive key derivation
    let mfa_time = lock_mfa_time(&app_state).map_err(|e| e.to_string())?.clone();
    let is_recent = mfa_time
        .map(|t| {
            let elapsed = t.elapsed();
            eprintln!("UNLOCK: Early MFA elapsed time: {:?}", elapsed);
            elapsed < std::time::Duration::from_secs(300)
        })
        .unwrap_or(false);
    let totp_secret_path = get_totp_secret_path(&app_handle).map_err(|e| e.to_string())?;
    eprintln!(
        "UNLOCK: Early MFA check - secret exists: {}, recent: {}",
        totp_secret_path.exists(),
        is_recent
    );
    if totp_secret_path.exists() && !is_recent {
        if let Err(err) = write_audit_log(
            &app_handle,
            "mfa_required_reject",
            "Unlock rejected before key derivation: recent TOTP verification required",
        ) {
            eprintln!("AUDIT WRITE ERROR: {}", err);
        }
        eprintln!("UNLOCK: Early MFA gate blocked unlock");
        return Err("TOTP required: please verify code before unlocking".into());
    }

    // Existing vault with error recovery and file locking
        // Existing vault with error recovery and file locking
        let contents = match File::open(&vault_path) {
            Ok(mut file) => {
                // Lock the file for reading to prevent concurrent modifications
                file.lock_shared().map_err(|_| "Vault file is locked by another process".to_string())?;
                
                let mut contents = String::new();
                file.read_to_string(&mut contents).map_err(|e| sanitize_error(&e.to_string()))?;
                
                // Unlock the file
                file.unlock().map_err(|_| "Failed to unlock vault file".to_string())?;
                
                contents
            },
            Err(_) => {
                // Try to restore from backup
                if restore_from_backup(&vault_path).map_err(|e| e.to_string())? {
                    let mut file = File::open(&vault_path).map_err(|e| format!("Failed to open vault after backup restore: {}", e))?;
                    file.lock_shared().map_err(|_| "Restored vault file is locked".to_string())?;
                    
                    let mut contents = String::new();
                    file.read_to_string(&mut contents).map_err(|e| e.to_string())?;
                    
                    file.unlock().map_err(|_| "Failed to unlock restored vault file".to_string())?;
                    
                    contents
                } else {
                    return Err("Vault file corrupted and no backup available".to_string());
                }
            }
        };
        eprintln!("UNLOCK: File read completed in {:?}", start_time.elapsed());
        
        let encrypted_vault: EncryptedVault = match serde_json::from_str(&contents) {
            Ok(vault) => vault,
            Err(_) => {
                // Try to restore from backup
                if restore_from_backup(&vault_path).map_err(|e| e.to_string())? {
                    let backup_contents = fs::read_to_string(&vault_path).map_err(|e| e.to_string())?;
                    serde_json::from_str(&backup_contents).map_err(|e| format!("Backup vault also corrupted: {}", e))?
                } else {
                    return Err("Vault JSON corrupted and no backup available".to_string());
                }
            }
        };
        
        // Check vault version compatibility
        if encrypted_vault.version > VAULT_VERSION {
            return Err("Vault was created with a newer version of the application".to_string());
        }
        
        let salt = BASE64.decode(encrypted_vault.salt).map_err(|e| e.to_string())?;
        let stored_verifier = BASE64.decode(encrypted_vault.verifier).map_err(|e| e.to_string())?;
        eprintln!("UNLOCK: JSON parsed and decoded in {:?}", start_time.elapsed());
        
        // Derive master key using vault-stored Argon2 parameters and verify password
        eprintln!("UNLOCK: Starting Argon2 key derivation...");
        let master_key = derive_master_key_with_params(&password, &salt, &encrypted_vault.argon2_params)
            .map_err(|e| e.to_string())?;
        eprintln!("UNLOCK: Argon2 key derivation completed in {:?}", start_time.elapsed());
        
        if !verify_master_key(&master_key, &salt, &stored_verifier).map_err(|e| e.to_string())? {
            eprintln!("UNLOCK: Password verification failed");
            return Err("Invalid password".to_string());
        }
        eprintln!("UNLOCK: Password verified in {:?}", start_time.elapsed());
        
        // Derive encryption key
        let (encryption_key, _) = derive_keys(&master_key, &salt).map_err(|e| e.to_string())?;
        eprintln!("UNLOCK: Encryption key derived in {:?}", start_time.elapsed());
        
        let encrypted_data = BASE64.decode(encrypted_vault.data).map_err(|e| e.to_string())?;
        let nonce = BASE64.decode(encrypted_vault.nonce).map_err(|e| e.to_string())?;
        let aad = BASE64.decode(encrypted_vault.aad).map_err(|e| e.to_string())?;
        
        let decrypted_data = decrypt_with_aad(&encrypted_data, &encryption_key, &nonce, &aad)
            .map_err(|_| "Failed to decrypt vault data")?;
        eprintln!("UNLOCK: Data decrypted in {:?}", start_time.elapsed());
        
        let payload: VaultPayload = match serde_json::from_slice::<VaultPayload>(&decrypted_data) {
            Ok(p) => p,
            Err(_) => {
                // Backward-compat: payload may be just entries Vec<PasswordEntry>
                let entries_only: Vec<PasswordEntry> = serde_json::from_slice(&decrypted_data).map_err(|e| e.to_string())?;
                VaultPayload { entries: entries_only, totp_account: None }
            }
        };

        // Master key available: proceed to set it and finalize unlock
        *lock_master_key(&app_state).map_err(|e| e.to_string())? = Some(master_key);
        
        // Log successful unlock (audit trail)
        if let Err(err) = write_audit_log(&app_handle, "vault_unlock", "Vault unlocked") {
            eprintln!("AUDIT WRITE ERROR: {}", err);
        }
        
        let mut vault = lock_vault_state(&app_state).map_err(|e| e.to_string())?;
        vault.entries = payload.entries.clone();
        vault.totp_account = payload.totp_account.clone();
        update_activity(&mut vault);
        vault.is_locked = false;
        
        eprintln!("UNLOCK: Vault unlocked successfully with {} entries in {:?}", payload.entries.len(), start_time.elapsed());
        eprintln!("=== UNLOCK_VAULT END ===");
        
        Ok(payload.entries)
}


#[tauri::command]
async fn add_entry(
    entry_data: serde_json::Value,
    app_state: State<'_, AppState>,
    app_handle: AppHandle,
) -> Result<Vec<PasswordEntry>, String> {
    println!("[DEBUG] Attempting to add entry");
    let mut vault = lock_vault_state(&app_state).map_err(|e| e.to_string())?;
    
    // Check session timeout
    if let Err(e) = check_session_timeout(&app_handle, &mut vault) {
        return Err(e.to_string());
    }
    
    // Update activity to prevent auto-lock during active use
    update_activity(&mut vault);
    
    // Update activity to prevent auto-lock during active use
    update_activity(&mut vault);
    
    if vault.is_locked {
        println!("[DEBUG] Add entry failed: Vault is locked.");
        return Err("Vault is locked".to_string());
    }

    let service = entry_data["service"].as_str().unwrap_or_default().to_string();
    let username = entry_data["username"].as_str().unwrap_or_default().to_string();
    let password = entry_data["password"].as_str().unwrap_or_default().to_string();
    let url = entry_data["url"].as_str().map(|s| s.to_string());
    let notes = entry_data["notes"].as_str().map(|s| s.to_string());

    let mut new_entry = PasswordEntry {
        id: uuid::Uuid::new_v4().to_string(),
        service,
        username,
        password,
        url,
        notes,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    // Sanitize and validate the new entry
    new_entry.service = sanitize_input(&new_entry.service);
    new_entry.username = sanitize_input(&new_entry.username);
    if let Some(url) = &new_entry.url {
        new_entry.url = Some(sanitize_input(url));
    }
    if let Some(notes) = &new_entry.notes {
        new_entry.notes = Some(sanitize_input(notes));
    }
    validate_password_entry(&new_entry).map_err(|e| e.to_string())?;
    println!("[DEBUG] Entry validated: {}", new_entry.service);

    vault.entries.push(new_entry.clone());
    update_activity(&mut vault);
    println!("[DEBUG] Entry added to in-memory vault. Attempting to save.");

    let updated_entries = vault.entries.clone();
    let entries_for_saving = vault.entries.clone();
    let totp_account = vault.totp_account.clone();
    drop(vault);

    let save_result = save_vault(&entries_for_saving, &totp_account, &app_state, &app_handle);
    match save_result {
        Ok(_) => {
            println!("[DEBUG] Vault saved successfully after adding entry.");
            if let Err(err) = write_audit_log(&app_handle, "add_entry", "Password entry added") {
                eprintln!("AUDIT WRITE ERROR: {}", err);
            }
            Ok(updated_entries)
        }
        Err(e) => {
            println!("[DEBUG] Save vault failed after adding entry: {:?}", e);
            Err(format!("Save failed: {}", e))
        }
    }
}

#[tauri::command]
async fn update_entry(
    mut entry: PasswordEntry,
    app_state: State<'_, AppState>,
    app_handle: AppHandle,
) -> Result<Vec<PasswordEntry>, String> {
    // Sanitize inputs
    entry.service = sanitize_input(&entry.service);
    entry.username = sanitize_input(&entry.username);
    entry.password = sanitize_input(&entry.password);
    if let Some(url) = &entry.url {
        entry.url = Some(sanitize_input(url));
    }
    if let Some(notes) = &entry.notes {
        entry.notes = Some(sanitize_input(notes));
    }
    
    // Validate entry
    validate_password_entry(&entry).map_err(|e| e.to_string())?;
    
    let mut vault = lock_vault_state(&app_state).map_err(|e| e.to_string())?;
    
    // Check session timeout
    if let Err(e) = check_session_timeout(&app_handle, &mut vault) {
        return Err(e.to_string());
    }
    
    // Update activity to prevent auto-lock during active use
    update_activity(&mut vault);
    
    if vault.is_locked {
        return Err("Vault is locked".to_string());
    }
    
    if let Some(index) = vault.entries.iter().position(|e| e.id == entry.id) {
        // Capture previous state for audit comparison
        let old = vault.entries[index].clone();
        
        // Update timestamp
        entry.updated_at = chrono::Utc::now();
        
        // Compute field-level changes
        let mut changes: Vec<String> = Vec::new();
        if old.service != entry.service {
            changes.push(format!("service: '{}' -> '{}'", old.service, entry.service));
        }
        if old.username != entry.username {
            changes.push(format!("username: '{}' -> '{}'", old.username, entry.username));
        }
        if old.password != entry.password {
            changes.push("password: [changed]".to_string());
        }
        let old_url = old.url.clone().unwrap_or_default();
        let new_url = entry.url.clone().unwrap_or_default();
        if old_url != new_url {
            changes.push(format!("url: '{}' -> '{}'", old_url, new_url));
        }
        let old_notes = old.notes.clone().unwrap_or_default();
        let new_notes = entry.notes.clone().unwrap_or_default();
        if old_notes != new_notes {
            changes.push("notes: [changed]".to_string());
        }
        
        // Audit log
        if !changes.is_empty() {
            let summary = format!(
                "Entry {} updated | {}",
                entry.id,
                changes.join("; ")
            );
            if let Err(err) = write_audit_log(&app_handle, "entry_update", &summary) {
                eprintln!("AUDIT WRITE ERROR: {}", err);
            }
        } else {
            let summary = format!(
                "Entry {} update called with no field changes",
                entry.id
            );
            if let Err(err) = write_audit_log(&app_handle, "entry_update", &summary) {
                eprintln!("AUDIT WRITE ERROR: {}", err);
            }
        }
        
        // Apply changes and persist
        vault.entries[index] = entry;
        save_vault(&vault.entries, &vault.totp_account, &app_state, &app_handle).map_err(|e| e.to_string())?;
        Ok(vault.entries.clone())
    } else {
        Err("Entry not found".to_string())
    }
}

#[tauri::command]
async fn delete_entry(id: String, app_state: State<'_, AppState>, app_handle: AppHandle) -> Result<Vec<PasswordEntry>, String> {
    let mut vault = lock_vault_state(&app_state).map_err(|e| e.to_string())?;
    
    // Check session timeout
    if let Err(e) = check_session_timeout(&app_handle, &mut vault) {
        return Err(e.to_string());
    }
    
    // Update activity to prevent auto-lock during active use
    update_activity(&mut vault);
    
    if vault.is_locked {
        return Err("Vault is locked".to_string());
    }
    
    if let Some(index) = vault.entries.iter().position(|e| e.id == id) {
        let removed = vault.entries[index].clone();
        vault.entries.remove(index);
        save_vault(&vault.entries, &vault.totp_account, &app_state, &app_handle).map_err(|e| e.to_string())?;
        if let Err(err) = write_audit_log(&app_handle, "entry_delete", &format!("Entry deleted (id={}, service={})", removed.id, removed.service)) {
            eprintln!("AUDIT WRITE ERROR: {}", err);
        }
        Ok(vault.entries.clone())
    } else {
        Err("Entry not found".to_string())
    }
}

#[tauri::command]
async fn lock_vault(app_state: State<'_, AppState>, app_handle: AppHandle) -> Result<(), String> {
    let mut vault = lock_vault_state(&app_state).map_err(|e| e.to_string())?;
    vault.is_locked = true;
    vault.entries.clear();
    
    // Explicit zeroization before removing key from state
    {
        let mut master_key_guard = app_state.master_key.lock().unwrap();
        if let Some(key) = master_key_guard.take() {
            // SecureKey zeroizes on drop; dropping clears key material
            drop(key);
        }
    }
    
    // Log vault lock (audit trail)
    if let Err(err) = write_audit_log(&app_handle, "vault_lock", "Vault locked") {
        eprintln!("AUDIT WRITE ERROR: {}", err);
    }
    Ok(())
}

// Removed auto_type_credentials function - no longer needed

#[tauri::command]
async fn enable_smart_clipboard(id: String, app_state: State<'_, AppState>, clipboard_manager: State<'_, SmartClipboardManager>, app_handle: AppHandle) -> Result<String, String> {
    // Extract credentials from vault
    let username: String;
    let password: String;
    
    {
        let vault = app_state.vault.lock().unwrap();
        if vault.is_locked {
            return Err("Vault is locked".to_string());
        }
        
        if let Some(entry) = vault.entries.iter().find(|e| e.id == id) {
            username = entry.username.clone();
            password = entry.password.clone();
        } else {
            return Err("Entry not found".to_string());
        }
    }
    
    // Copy username to clipboard
    let mut clipboard = Clipboard::new().map_err(|_| "Clipboard access failed".to_string())?;
    clipboard.set_text(&username).map_err(|_| "Failed to copy to clipboard".to_string())?;
    
    // Audit log
    if let Err(err) = write_audit_log(&app_handle, "smart_clipboard_enabled", &format!("Smart clipboard enabled - username copied for entry '{}'", id)) {
        eprintln!("AUDIT WRITE ERROR: {}", err);
    }
    
    // Store credentials for later use
    {
        let mut state = clipboard_manager.state.write().await;
        state.is_active = true;
        state.username = username.clone();
        state.password = password;
        state.last_username_copy = Some(Instant::now());
        state.expected_clipboard_content = username.clone();
        state.interference_detected = false;
    }
    
    Ok("Username copied. Paste it in your browser, then we'll auto-type the password.".to_string())
}



// Clipboard interference detection function
async fn monitor_clipboard_changes(clipboard_manager: Arc<SmartClipboardManager>) {
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await; // Check every 500ms

        // Snapshot state for decisions
        let expected;
        let mut last_copy_elapsed: Option<Duration> = None;
        let active;
        {
            let state = clipboard_manager.state.read().await;
            active = state.is_active;
            expected = state.expected_clipboard_content.clone();
            if let Some(t) = state.last_username_copy {
                last_copy_elapsed = Some(t.elapsed());
            }
        }

        if !active {
            continue;
        }

        // Auto-clear after configured delay
        if let Some(elapsed) = last_copy_elapsed {
            if elapsed >= CLIPBOARD_AUTO_CLEAR_AFTER {
                if let Ok(mut clipboard) = Clipboard::new() {
                    let _ = clipboard.set_text("");
                }
                let mut state = clipboard_manager.state.write().await;
                state.is_active = false;
                state.username.clear();
                state.password.clear();
                state.expected_clipboard_content.clear();
                state.last_username_copy = None;
                state.interference_detected = false;
                continue;
            }
        }

        // Interference detection and restoration
        if expected.is_empty() {
            continue;
        }
        if let Ok(mut clipboard) = Clipboard::new() {
            if let Ok(current_content) = clipboard.get_text() {
                let restore_allowed = match last_copy_elapsed {
                    Some(elapsed) => elapsed > Duration::from_secs(1),
                    None => true,
                };
                if restore_allowed && current_content != expected {
                    let mut state = clipboard_manager.state.write().await;
                    state.interference_detected = true;
                    let _ = clipboard.set_text(&expected);
                }
            }
        }
    }
}



#[tauri::command]
async fn copy_username(id: String, app_state: State<'_, AppState>, app_handle: AppHandle) -> Result<String, String> {
    let vault = app_state.vault.lock().unwrap();
    if vault.is_locked {
        return Err("Vault is locked".to_string());
    }
    
    if let Some(entry) = vault.entries.iter().find(|e| e.id == id) {
        // Copy username to clipboard
        let mut clipboard = Clipboard::new().map_err(|e| format!("Clipboard error: {}", e))?;
        clipboard.set_text(&entry.username).map_err(|e| format!("Failed to copy username: {}", e))?;
        
        // Audit log
        if let Err(err) = write_audit_log(&app_handle, "copy_username", &format!("Username copied for service '{}' (entry_id={})", 
                 entry.service, entry.id)) {
            eprintln!("AUDIT WRITE ERROR: {}", err);
        }
        
        Ok(format!("Username copied for {}", entry.service))
    } else {
        Err("Entry not found".to_string())
    }
}

#[tauri::command]
async fn copy_password(id: String, app_state: State<'_, AppState>, app_handle: AppHandle) -> Result<String, String> {
    let vault = app_state.vault.lock().unwrap();
    if vault.is_locked {
        return Err("Vault is locked".to_string());
    }
    
    if let Some(entry) = vault.entries.iter().find(|e| e.id == id) {
        // Copy password to clipboard
        let mut clipboard = Clipboard::new().map_err(|e| format!("Clipboard error: {}", e))?;
        clipboard.set_text(&entry.password).map_err(|e| format!("Failed to copy password: {}", e))?;
        
        // Audit log (don't log the actual password)
        if let Err(err) = write_audit_log(&app_handle, "copy_password", &format!("Password copied for service '{}' (entry_id={})", 
                 entry.service, entry.id)) {
            eprintln!("AUDIT WRITE ERROR: {}", err);
        }
        
        Ok(format!("Password copied for {}", entry.service))
    } else {
        Err("Entry not found".to_string())
    }
}



#[tauri::command]
async fn check_clipboard_interference(clipboard_manager: State<'_, SmartClipboardManager>, app_handle: AppHandle) -> Result<bool, String> {
    let mut state = clipboard_manager.state.write().await;
    let interference_detected = state.interference_detected;
    if interference_detected {
        if let Err(err) = write_audit_log(&app_handle, "clipboard_interference_detected", "Clipboard interference detected during smart mode") {
            eprintln!("AUDIT WRITE ERROR: {}", err);
        }
        // Reset the flag after reporting
        state.interference_detected = false;
    }
    Ok(interference_detected)
}

#[tauri::command]
async fn delete_vault(app_state: State<'_, AppState>, app_handle: AppHandle) -> Result<(), String> {
    let vault_path = get_vault_path(&app_handle).map_err(|e| e.to_string())?;

    // Lock the vault first and explicitly zeroize keys
    {
        let mut vault = app_state.vault.lock().unwrap();
        vault.is_locked = true;
        vault.entries.clear();

        // Explicit zeroization before removing key from state
        let mut master_key_guard = app_state.master_key.lock().unwrap();
        if let Some(key) = master_key_guard.take() {
            // SecureKey zeroizes on drop; dropping clears key material
            drop(key);
        }
    }

    // Log vault deletion (audit trail)
    if let Err(err) = write_audit_log(&app_handle, "vault_delete", "Vault deleted") {
        eprintln!("AUDIT WRITE ERROR: {}", err);
    }

    // Delete the vault file if it exists, with retries
    if vault_path.exists() {
        let mut attempts = 0;
        while attempts < 3 {
            match fs::remove_file(&vault_path) {
                Ok(_) => break,
                Err(e) => {
                    attempts += 1;
                    if attempts >= 3 {
                        return Err(format!("Failed to delete vault file after 3 attempts: {}", e));
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    // Also delete backup if it exists
    let backup_path = vault_path.with_extension("enc.backup");
    if backup_path.exists() {
        let _ = fs::remove_file(&backup_path); // Don't fail if backup deletion fails
    }

    // Also delete TOTP secret if it exists
    let totp_secret_path = get_totp_secret_path(&app_handle).map_err(|e| e.to_string())?;
    if totp_secret_path.exists() {
        let _ = fs::remove_file(&totp_secret_path); // Don't fail if deletion fails
    }

    Ok(())
}

// Export the encrypted vault.enc to a user-specified path
#[tauri::command]
async fn export_vault_file(dest_path: String, app_handle: AppHandle) -> Result<(), String> {
    let vault_path = get_vault_path(&app_handle).map_err(|e| e.to_string())?;
    if !vault_path.exists() {
        return Err("Vault file not found".to_string());
    }

    // Read current vault under a shared lock and validate JSON
    let mut src_file = OpenOptions::new().read(true).open(&vault_path).map_err(|e| e.to_string())?;
    src_file.lock_shared().map_err(|_| "Vault file is locked by another process".to_string())?;
    let mut contents = String::new();
    src_file.read_to_string(&mut contents).map_err(|e| e.to_string())?;
    src_file.unlock().map_err(|_| "Failed to unlock vault file".to_string())?;
    // Explicitly drop the file handle to avoid Windows deletion/rename errors when exporting to the same directory
    drop(src_file);

    if serde_json::from_str::<EncryptedVault>(&contents).is_err() {
        return Err("Vault file is corrupted".to_string());
    }

    let dest = PathBuf::from(dest_path);
    if let Some(parent) = dest.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    }

    // Ensure destination drive has enough free space
    check_disk_space(&dest).map_err(|e| e.to_string())?;

    // Atomic write to destination via temporary file
    let temp = dest.with_extension("tmp");
    {
        let mut temp_file = File::create(&temp).map_err(|e| e.to_string())?;
        temp_file.lock_exclusive().map_err(|_| "Failed to lock temporary file".to_string())?;
        temp_file.write_all(contents.as_bytes()).map_err(|e| e.to_string())?;
        temp_file.sync_all().map_err(|e| e.to_string())?;
        temp_file.unlock().map_err(|_| "Failed to unlock temporary file".to_string())?;
    }

    // Replace if destination exists
    if dest.exists() {
        fs::remove_file(&dest).map_err(|e| e.to_string())?;
    }
    fs::rename(&temp, &dest).map_err(|e| e.to_string())?;

    // Audit
    let _ = write_audit_log(&app_handle, "vault_export", &format!("Vault exported to {}", dest.display()));
    Ok(())
}

// Import an encrypted vault file and replace current vault.enc atomically
#[tauri::command]
async fn import_vault_file(src_path: String, app_state: State<'_, AppState>, app_handle: AppHandle) -> Result<(), String> {
    let src = PathBuf::from(src_path);
    if !src.exists() {
        return Err("Source file not found".to_string());
    }

    // Read source file under shared lock and validate JSON
    let mut src_file = OpenOptions::new().read(true).open(&src).map_err(|e| e.to_string())?;
    src_file.lock_shared().map_err(|_| "Source file is locked by another process".to_string())?;
    let mut contents = String::new();
    src_file.read_to_string(&mut contents).map_err(|e| e.to_string())?;
    src_file.unlock().map_err(|_| "Failed to unlock source file".to_string())?;

    match serde_json::from_str::<EncryptedVault>(&contents) {
        Ok(_) => {}
        Err(_) => return Err("Invalid vault file format".to_string()),
    }

    let vault_path = get_vault_path(&app_handle).map_err(|e| e.to_string())?;

    // Check free space on vault drive and create backup if current vault exists
    check_disk_space(&vault_path).map_err(|e| e.to_string())?;
    if vault_path.exists() {
        create_backup(&vault_path).map_err(|e| e.to_string())?;
    }

    // Reset in-memory state and zeroize master key before replacing vault file
    {
        let mut vault = app_state.vault.lock().unwrap();
        vault.is_locked = true;
        vault.entries.clear();
        vault.totp_account = None;
        let mut master_key_guard = app_state.master_key.lock().unwrap();
        if let Some(key) = master_key_guard.take() {
            drop(key);
        }
    }

    // Atomic replace using temporary file in the same directory
    let temp = vault_path.with_extension("tmp");
    {
        let mut temp_file = File::create(&temp).map_err(|e| e.to_string())?;
        temp_file.lock_exclusive().map_err(|_| "Failed to lock temporary file".to_string())?;
        temp_file.write_all(contents.as_bytes()).map_err(|e| e.to_string())?;
        temp_file.sync_all().map_err(|e| e.to_string())?;
        temp_file.unlock().map_err(|_| "Failed to unlock temporary file".to_string())?;
    }

    if vault_path.exists() {
        let orig = OpenOptions::new().read(true).open(&vault_path).map_err(|e| e.to_string())?;
        orig.lock_exclusive().map_err(|_| "Vault file is locked by another process".to_string())?;
        orig.unlock().map_err(|_| "Failed to unlock vault file".to_string())?;
        let _ = fs::remove_file(&vault_path);
    }

    fs::rename(&temp, &vault_path).map_err(|e| e.to_string())?;

    // Audit
    let _ = write_audit_log(&app_handle, "vault_import", &format!("Vault imported from {}", src.display()));

    Ok(())
}

#[tauri::command]
async fn set_totp_account(
    account_name: String,
    issuer: String,
    app_state: State<'_, AppState>,
    app_handle: AppHandle,
) -> Result<(), String> {
    let mut vault = app_state.vault.lock().unwrap();
    if vault.is_locked {
        return Err("Vault is locked".to_string());
    }

    let totp_account = TotpAccount {
        username: "user".to_string(), // Placeholder, adjust as needed
        password: "".to_string(),      // Placeholder, adjust as needed
        issuer,
        account_name,
    };
    vault.totp_account = Some(totp_account.clone());
    vault.last_activity = Instant::now();

    let entries_for_saving = vault.entries.clone();
    drop(vault);

    save_vault(&entries_for_saving, &Some(totp_account), &app_state, &app_handle)
        .map_err(|e| e.to_string())?;

    if let Err(err) = write_audit_log(&app_handle, "set_totp_account", "TOTP account details updated") {
        eprintln!("AUDIT WRITE ERROR: {}", err);
    }

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct InitTotpResponse {
    uri: String,
    secret: String,
}

#[tauri::command]
async fn init_totp(app_state: State<'_, AppState>, _app_handle: AppHandle) -> Result<InitTotpResponse, String> {
    // Generate a new secret
    let secret = Secret::generate_secret();
    let secret_bytes = secret.to_bytes().map_err(|e| e.to_string())?;

    // Read issuer/account from vault (fallbacks if missing)
    let mut vault = app_state.vault.lock().unwrap();
    if vault.is_locked {
        return Err("Vault is locked".to_string());
    }
    vault.last_activity = Instant::now();
    let (issuer, account) = if let Some(ref acct) = vault.totp_account {
        (acct.issuer.clone(), acct.account_name.clone())
    } else {
        ("SecurePasswordManager".to_string(), "user".to_string())
    };
    drop(vault);

    let totp = TOTP::new(TOTPAlgorithm::SHA1, 6, 1, 30, secret_bytes.clone(), Some(account.clone()), issuer.clone())
        .map_err(|e| e.to_string())?;
    let uri = totp.get_url();

    Ok(InitTotpResponse { uri, secret: BASE64.encode(&secret_bytes) })
}

#[tauri::command]
async fn finalize_totp(secret: String, app_state: State<'_, AppState>, app_handle: AppHandle) -> Result<(), String> {
    // Update last activity to keep session alive
    let mut vault = app_state.vault.lock().unwrap();
    if vault.is_locked {
        return Err("Vault is locked".to_string());
    }
    vault.last_activity = Instant::now();
    drop(vault);
    let secret_bytes = BASE64.decode(&secret).map_err(|e| e.to_string())?;

    // Protect secret bytes with DPAPI and save to file
    let secret_path = get_totp_secret_path(&app_handle).map_err(|e| e.to_string())?;
    if let Err(err) = check_disk_space(&secret_path) {
        eprintln!("Warning: disk space check failed for TOTP secret: {}", err);
    }
    let protected = dpapi_protect(&secret_bytes).map_err(|e| e.to_string())?;
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&secret_path)
        .map_err(|e| e.to_string())?;
    file.write_all(&protected).map_err(|e| e.to_string())?;

    let _ = write_audit_log(&app_handle, "mfa_provision", "TOTP secret provisioned and stored with DPAPI");
    Ok(())
}

#[tauri::command]
async fn verify_totp(code: String, secret: Option<String>, app_state: State<'_, AppState>, app_handle: AppHandle) -> Result<bool, String> {
    let secret_bytes = if let Some(s) = secret {
        BASE64.decode(&s).map_err(|e| e.to_string())?
    } else {
        // Load protected secret bytes from file if not provided
        let secret_path = get_totp_secret_path(&app_handle).map_err(|e| e.to_string())?;
        if !secret_path.exists() {
            return Err("TOTP not provisioned".into());
        }
        let mut buf = Vec::new();
        let mut f = File::open(&secret_path).map_err(|e| e.to_string())?;
        f.read_to_end(&mut buf).map_err(|e| e.to_string())?;
        dpapi_unprotect(&buf).map_err(|e| e.to_string())?
    };

    // Use issuer/account from vault for consistency, but allow TOTP verification even when locked
    let mut vault = app_state.vault.lock().unwrap();
    // Don't check if vault is locked - TOTP verification should work when vault is locked!
    if !vault.is_locked {
        vault.last_activity = Instant::now();
    }
    let (issuer, account) = if let Some(ref acct) = vault.totp_account {
        (acct.issuer.clone(), acct.account_name.clone())
    } else {
        ("SecurePasswordManager".to_string(), "user".to_string())
    };
    drop(vault);

    // Build TOTP and verify
    let totp = TOTP::new(
        TOTPAlgorithm::SHA1,
        6,
        1,
        30,
        secret_bytes, // Use the raw bytes directly
        Some(account.clone()),
        issuer.clone(),
    ).map_err(|e| e.to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ok = totp.check(&code, now);

    if ok {
        let mut mfa = app_state.mfa_verified_at.lock().unwrap();
        let now = Instant::now();
        *mfa = Some(now);
        println!("MFA verification successful, timestamp set to: {:?}", now);
        let _ = write_audit_log(&app_handle, "mfa_verify", "TOTP verification succeeded");
    } else {
        println!("MFA verification failed for code: {}", code);
        let _ = write_audit_log(&app_handle, "mfa_verify", "TOTP verification failed");
    }
    Ok(ok)
}
#[tauri::command]
async fn totp_account_status(app_handle: AppHandle) -> Result<bool, String> {
    let secret_path = get_totp_secret_path(&app_handle).map_err(|e| e.to_string())?;
    Ok(secret_path.exists())
}

#[tauri::command]
async fn keep_session_alive(app_state: State<'_, AppState>) -> Result<(), String> {
    let mut vault = app_state.vault.lock().unwrap();
    if vault.is_locked {
        return Err("Vault is locked".to_string());
    }
    vault.last_activity = Instant::now();
    Ok(())
}

#[tauri::command]
async fn trigger_password_autotype(clipboard_manager: State<'_, SmartClipboardManager>, app_handle: AppHandle) -> Result<(), String> {
    let mut state = clipboard_manager.state.write().await;
    if state.is_active {
        // Prevent auto-type if interference was detected
        if state.interference_detected {
            if let Err(err) = write_audit_log(&app_handle, "autotype_skipped_interference", "Auto-type skipped due to clipboard interference") {
                eprintln!("AUDIT WRITE ERROR: {}", err);
            }
            return Err("Clipboard interference detected. Auto-type aborted.".to_string());
        }

        // Type the password
        let password_to_type = state.password.clone();
        if let Err(err) = write_audit_log(&app_handle, "autotype_triggered", "Auto-typing password") {
            eprintln!("AUDIT WRITE ERROR: {}", err);
        }
        
        // Use enigo to type the password
        tokio::task::spawn_blocking(move || {
            let mut enigo = Enigo::new(&Settings::default()).unwrap();
            // Press Tab to move to the password field
            enigo.key(EnigoKey::Tab, enigo::Direction::Click).unwrap();
            // Type the password
            enigo.text(&password_to_type).unwrap();
        }).await.map_err(|e| e.to_string())?;

        // Deactivate smart clipboard after auto-typing
        state.is_active = false;
        state.username.clear();
        state.password.clear();
        state.last_username_copy = None;
        state.expected_clipboard_content.clear();
        state.interference_detected = false;
        
        // Clear clipboard for security
        let mut clipboard = Clipboard::new().map_err(|e| format!("Clipboard error: {}", e))?;
        clipboard.set_text("").map_err(|e| format!("Failed to clear clipboard: {}", e))?;
    }
    Ok(())
}

// Native Ctrl+V detection removed due to compilation issues with cross-platform keyboard libraries
// The frontend-based detection using JavaScript events is working effectively instead

// Global Ctrl+V detection function
struct GlobalKeyState {
    ctrl_pressed: bool,
}

async fn monitor_global_keys(clipboard_state: Arc<RwLock<SmartClipboardState>>) {
    let key_state = Arc::new(RwLock::new(GlobalKeyState {
        ctrl_pressed: false,
    }));

    let key_state_clone = key_state.clone();
    let clipboard_manager_clone = clipboard_state.clone();

    // Create a Tokio runtime for the key listener thread
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let callback = move |event: Event| {
            let key_state = key_state_clone.clone();
            let clipboard_manager = clipboard_manager_clone.clone();
            let rt_handle = rt.handle().clone();

            rt_handle.spawn(async move {
                match event.event_type {
                    EventType::KeyPress(RdevKey::ControlLeft) | EventType::KeyPress(RdevKey::ControlRight) => {
                        let mut state = key_state.write().await;
                        state.ctrl_pressed = true;
                        println!("[DEBUG] Ctrl key pressed");
                    }
                    EventType::KeyRelease(RdevKey::ControlLeft) | EventType::KeyRelease(RdevKey::ControlRight) => {
                        let mut state = key_state.write().await;
                        state.ctrl_pressed = false;
                        println!("[DEBUG] Ctrl key released");
                    }
                    EventType::KeyPress(RdevKey::KeyV) => {
                        let key_state_read = key_state.read().await;
                        if key_state_read.ctrl_pressed {
                            println!("[DEBUG] Global Ctrl+V detected!");

                            // Check if smart clipboard is active
                            let clipboard_state = clipboard_manager.read().await;
                            if clipboard_state.is_active && !clipboard_state.password.is_empty() {
                                println!("[DEBUG] Smart clipboard active, triggering autotype sequence");

                                // Clone the password for the autotype sequence
                                let password = clipboard_state.password.clone();
                                drop(clipboard_state); // Release the read lock

                                // Start the autotype sequence after a delay
                                tokio::spawn(async move {
                                    // Wait for user to paste username
                                    tokio::time::sleep(Duration::from_millis(700)).await;

                                    // Press TAB to move to password field
                                    println!("[DEBUG] Pressing TAB key");
                                    let mut enigo = Enigo::new(&Settings::default()).unwrap();
                                    for _ in 0..3 {
                                        if let Err(e) = enigo.key(EnigoKey::Tab, enigo::Direction::Click) {
                                            println!("[DEBUG] Failed to press TAB: {}", e);
                                        } else {
                                            break;
                                        }
                                        tokio::time::sleep(Duration::from_millis(100)).await;
                                    }

                                    // Wait before typing password
                                    tokio::time::sleep(Duration::from_millis(300)).await;

                                    // Type the password
                                    println!("[DEBUG] Typing password");
                                    for _ in 0..3 {
                                        if let Err(e) = enigo.text(&password) {
                                            println!("[DEBUG] Failed to type password: {}", e);
                                        } else {
                                            break;
                                        }
                                        tokio::time::sleep(Duration::from_millis(100)).await;
                                    }

                                    println!("[DEBUG] Enhanced autotype completed");
                                });

                                // Deactivate smart clipboard
                                let mut state = clipboard_manager.write().await;
                                state.is_active = false;
                                state.username.clear();
                                state.password.clear();
                            }
                        }
                    }
                    _ => {}
                }
            });
        };

        // Start listening for global key events
        if let Err(err) = listen(callback) {
            println!("[ERROR] Global key listener error: {:?}", err);
        }
    });
}

// Atomic save_vault function with temporary file and atomic rename
fn save_vault(entries: &[PasswordEntry], totp_account: &Option<TotpAccount>, app_state: &AppState, app_handle: &AppHandle) -> Result<(), VaultError> {
    println!("[DEBUG] Saving vault...");
    let master_key = {
        let guard = app_state.master_key.lock().unwrap();
        guard.clone().ok_or(VaultError::NotUnlocked)?
    };
    println!("[DEBUG] Master key retrieved.");

    let vault_path = get_vault_path(app_handle)?;
    println!("[DEBUG] Vault path: {:?}", vault_path);
    
    // Check available disk space before proceeding
    check_disk_space(&vault_path)?;
    println!("[DEBUG] Disk space checked.");
    
    // Create backup before modifying vault
    create_backup(&vault_path)?;
    println!("[DEBUG] Backup created.");

    // Read existing vault metadata. If it doesn't exist or is corrupt, we can't proceed.
    let (salt_bytes, verifier, aad, argon2_params) = if vault_path.exists() {
        let contents = fs::read_to_string(&vault_path)?;
        match serde_json::from_str::<EncryptedVault>(&contents) {
            Ok(existing) => (
                BASE64.decode(existing.salt).map_err(|_| VaultError::Corrupted)?,
                BASE64.decode(existing.verifier).map_err(|_| VaultError::Corrupted)?,
                BASE64.decode(existing.aad).map_err(|_| VaultError::Corrupted)?,
                existing.argon2_params,
            ),
            Err(_) => return Err(VaultError::Corrupted), // If vault is corrupted, we can't save.
        }
    } else {
        // This case should ideally not be hit if create_vault was called first.
        return Err(VaultError::NotFound);
    };

    // Derive encryption key
    let (encryption_key, _) = derive_keys(&master_key, &salt_bytes)?;
    println!("[DEBUG] Encryption key derived.");

    let payload = VaultPayload { entries: entries.to_vec(), totp_account: totp_account.clone() };
    let vault_data = serde_json::to_vec(&payload)?;
    let (encrypted_data, nonce) = encrypt_with_aad(&vault_data, &encryption_key, &aad)?;
    println!("[DEBUG] Vault data encrypted.");

    let encrypted_vault = EncryptedVault {
        version: VAULT_VERSION,
        argon2_params,
        salt: BASE64.encode(&salt_bytes),
        nonce: BASE64.encode(&nonce),
        data: BASE64.encode(&encrypted_data),
        verifier: BASE64.encode(&verifier),
        aad: BASE64.encode(&aad),
    };

    let json = serde_json::to_string(&encrypted_vault)?;
    println!("[DEBUG] Encrypted vault serialized to JSON.");
    
    // Atomic file operation: write to temporary file first
    let temp_path = vault_path.with_extension("tmp");
    
    // Write to temporary file
    {
        let mut temp_file = File::create(&temp_path)?;
        
        // Lock the temporary file to prevent concurrent access
        temp_file.lock_exclusive().map_err(|_| VaultError::FileLocked)?;
        println!("[DEBUG] Temporary file locked.");
        
        temp_file.write_all(json.as_bytes())?;
        temp_file.sync_all()?; // Ensure data is written to disk
        println!("[DEBUG] Data written to temporary file.");
        
        // Unlock before closing
        temp_file.unlock().map_err(|_| VaultError::IoError(std::io::Error::new(std::io::ErrorKind::Other, "Failed to unlock file")))?;
        println!("[DEBUG] Temporary file unlocked.");
    }
    
    // Atomic rename - this is atomic on most filesystems
    fs::rename(&temp_path, &vault_path)?;
    println!("[DEBUG] Vault saved successfully.");

    Ok(())
}


// Auto-lock check task
async fn check_auto_lock(handle: tauri::AppHandle) {
    loop {
        sleep(Duration::from_secs(30)).await; // Check every 30 seconds
        let app_state = handle.state::<AppState>();
        let mut vault = app_state.vault.lock().unwrap();
        if !vault.is_locked && vault.last_activity.elapsed() > INACTIVITY_TIMEOUT {
            vault.is_locked = true;
            vault.entries.clear();
            
            // Explicit zeroization before removing key from state
            let mut master_key_guard = app_state.master_key.lock().unwrap();
            if let Some(key) = master_key_guard.take() {
                // SecureKey zeroizes on drop; dropping clears key material
                drop(key);
            }
            
            // Log auto-lock (audit trail)
            if let Err(err) = write_audit_log(&handle, "auto_lock", "Vault auto-locked due to inactivity") {
                eprintln!("AUDIT WRITE ERROR: {}", err);
            }
            
            // Emit auto-lock event for frontend
            let _ = handle.emit("vault_auto_locked", serde_json::json!({ "reason": "inactivity" }));
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Check if we should run in native messaging mode
    let args: Vec<String> = std::env::args().collect();
    
    // Check for native messaging mode indicators
    // Robust detection: explicit flag or chrome-extension origin, or stdin is a pipe (native messaging), but do not rely on parent-window or args length.
    #[cfg(windows)]
    let stdin_is_pipe = unsafe {
        let handle = GetStdHandle(STD_INPUT_HANDLE);
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            false
        } else {
            let ft = GetFileType(handle);
            ft == FILE_TYPE_PIPE
        }
    };
    #[cfg(not(windows))]
    let stdin_is_pipe = !std::io::stdin().is_terminal();

    let is_native_messaging = args.iter().any(|arg| 
        arg.starts_with("chrome-extension://") ||
        arg == "--native-messaging"
    ) || std::env::var("CHROME_NATIVE_MESSAGING").is_ok() || stdin_is_pipe;
    
    if is_native_messaging {
        eprintln!("Starting in native messaging mode");
        // Run in native messaging mode
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Create a minimal app handle for native messaging
            let app_state = AppState {
                vault: Mutex::new(VaultState {
                    entries: Vec::new(),
                    totp_account: None,
                    last_activity: Instant::now(),
                    is_locked: true,
                    // Extend session timeout for native messaging usage to reduce frequent unlocks
                    session_timeout_minutes: 60,
                }),
                master_key: Mutex::new(None),
                mfa_verified_at: Mutex::new(None),
            };
            
            // Create a temporary Tauri app for native messaging
            let app = tauri::Builder::default()
                .manage(app_state)
                .build(tauri::generate_context!())
                .expect("Failed to build Tauri app for native messaging");
            
            let handle = app.handle();
            if let Err(e) = native_messaging::run_native_messaging_host(handle.clone()).await {
                eprintln!("Native messaging host error: {}", e);
            }
        });
        return;
    }
    
    eprintln!("Starting in GUI mode");
    // Memory locking is handled where appropriate
    
    let app_state = AppState {
        vault: Mutex::new(VaultState {
            entries: Vec::new(),
            totp_account: None,
            last_activity: Instant::now(),
            is_locked: true,
            session_timeout_minutes: 3, // Default 3 minutes timeout
        }),
        master_key: Mutex::new(None),
        mfa_verified_at: Mutex::new(None),
    };

    let clipboard_manager = SmartClipboardManager {
        state: Arc::new(RwLock::new(SmartClipboardState {
            is_active: false,
            username: String::new(),
            password: String::new(),
            last_username_copy: None,
            expected_clipboard_content: String::new(),
            interference_detected: false,
        })),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .manage(app_state)
        .manage(clipboard_manager)
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            create_vault,
            unlock_vault,
            add_entry,
            update_entry,
            delete_entry,
            copy_username,
            copy_password,
            lock_vault,
            delete_vault,
            export_vault_file,
            import_vault_file,
            enable_smart_clipboard,
            trigger_password_autotype,
            check_clipboard_interference,
            init_totp,
            finalize_totp,
            verify_totp,
            set_totp_account,
            totp_account_status,
            keep_session_alive,
        ])
        .setup(|app| {
            let handle = app.handle();
            // Initialize session log file.log (truncate each session)
            if let Err(err) = init_audit_log(&handle) {
                eprintln!("AUDIT WRITE ERROR: {}", err);
            } else {
                let _ = write_audit_log(&handle, "app_start", "Password Manager application started");
                let _ = write_audit_log(&handle, "actions_available", "vault_exists, create_vault, unlock_vault, add_entry, update_entry, delete_entry, copy_username, copy_password, lock_vault, delete_vault, enable_smart_clipboard, trigger_password_autotype, check_clipboard_interference, init_totp, finalize_totp, verify_totp, set_totp_account, totp_account_status, keep_session_alive, export_vault_file, import_vault_file");
            }
            let handle_clone = handle.clone();
            tauri::async_runtime::spawn(check_auto_lock(handle_clone));

            // Start singleton smart clipboard monitors
            let cm_state = app.state::<SmartClipboardManager>().state.clone();
            let cm2 = SmartClipboardManager { state: cm_state.clone() };
            tauri::async_runtime::spawn(monitor_clipboard_changes(Arc::new(cm2)));

            let clipboard_manager_for_keys = app.state::<SmartClipboardManager>().state.clone();
            tauri::async_runtime::spawn(monitor_global_keys(clipboard_manager_for_keys));

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[derive(Serialize)]
struct AuditRecord<'a> {
    timestamp: String,
    category: &'a str,
    message: &'a str,
}

fn write_audit_log(app_handle: &AppHandle, category: &str, message: &str) -> Result<(), VaultError> {
    let vault_path = get_vault_path(app_handle)?;
    let log_dir = vault_path.parent().unwrap_or(std::path::Path::new("."));
    let log_path = log_dir.join("file.log");

    let timestamp = chrono::Utc::now().to_rfc3339();
    let record = AuditRecord { timestamp, category, message };
    let json = serde_json::to_string(&record)?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    writeln!(file, "{}", json)?;
    Ok(())
}

fn init_audit_log(app_handle: &AppHandle) -> Result<(), VaultError> {
    let vault_path = get_vault_path(app_handle)?;
    let log_dir = vault_path.parent().unwrap_or(std::path::Path::new("."));
    let log_path = log_dir.join("file.log");

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&log_path)?;

    let header = format!("Session started at {}\n", chrono::Utc::now().to_rfc3339());
    file.write_all(header.as_bytes())?;
    Ok(())
}

// Native Messaging Module for Browser Extension Communication
pub mod native_messaging {
    use super::*;
    use std::io::{self, Read, Write};
    use byteorder::{NativeEndian, ReadBytesExt, WriteBytesExt};
    use aes_gcm::{Aes256Gcm, aead::Aead, KeyInit, Nonce};
    
    #[derive(Serialize, Deserialize, Debug)]
    #[serde(tag = "type")]
    pub enum ExtensionMessage {
        #[serde(rename = "Authenticate")]
        Authenticate {
            extension_id: String,
            origin: String,
        },
        #[serde(rename = "SearchCredentials")]
        SearchCredentials {
            domain: String,
            url: String,
        },
        #[serde(rename = "SearchCredentialsWithPassword")]
        SearchCredentialsWithPassword {
            domain: String,
            url: String,
            master_password: String,
        },
        #[serde(rename = "VerifyTotp")]
        VerifyTotp {
            code: String,
        },
        #[serde(rename = "SaveCredential")]
        SaveCredential {
            domain: String,
            username: String,
            password: String,
            url: String,
        },
        #[serde(rename = "GeneratePassword")]
        GeneratePassword {
            options: PasswordGenerationOptions,
        },
        #[serde(rename = "GetPassword")]
        GetPassword {
            credential_id: String,
            session_token: String,
        },
        #[serde(rename = "GetVaultStatus")]
        GetVaultStatus,
        #[serde(rename = "UnlockWithDeviceKey")]
        UnlockWithDeviceKey,
        #[serde(rename = "UnlockVault")]
        UnlockVault {
            master_password: String,
        },
        #[serde(rename = "EnableDeviceUnlock")]
        EnableDeviceUnlock,
    }
    
    #[derive(Serialize, Deserialize, Debug)]
    #[serde(tag = "type")]
    pub enum ExtensionResponse {
        #[serde(rename = "authenticationResult")]
        AuthenticationResult {
            success: bool,
            session_token: Option<String>,
            encryption_key: Option<String>,
            error: Option<String>,
        },
        #[serde(rename = "credentialsResult")]
        CredentialsResult {
            success: bool,
            credentials: Option<Vec<CredentialMatch>>,
            error: Option<String>,
        },
        #[serde(rename = "totpResult")]
        TotpResult {
            success: bool,
            error: Option<String>,
        },
        #[serde(rename = "saveResult")]
        SaveResult {
            success: bool,
            error: Option<String>,
        },
        #[serde(rename = "passwordResult")]
        PasswordResult {
            success: bool,
            password: Option<String>,
            encrypted_password: Option<String>,
            nonce: Option<String>,
            error: Option<String>,
        },
        #[serde(rename = "vaultStatusResult")]
        VaultStatusResult {
            is_unlocked: bool,
            vault_exists: bool,
        },
        #[serde(rename = "unlockResult")]
        UnlockResult {
            success: bool,
            error: Option<String>,
        },
        #[serde(rename = "unlockRequired")]
        UnlockRequired {
            message: String,
        },
    }
    
    #[derive(Serialize, Deserialize, Debug)]
    pub struct CredentialMatch {
        pub id: String,
        pub username: String,
        pub domain: String,
        pub url: String,
        pub last_used: Option<DateTime<Utc>>,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PasswordGenerationOptions {
        pub length: usize,
        pub include_uppercase: bool,
        pub include_lowercase: bool,
        pub include_numbers: bool,
        pub include_symbols: bool,
    }
    
    // Session management for extension authentication
    use std::sync::LazyLock;
    static EXTENSION_SESSIONS: LazyLock<Mutex<std::collections::HashMap<String, ExtensionSession>>> = LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
    #[allow(dead_code)]
    static RATE_LIMITER: LazyLock<Mutex<std::collections::HashMap<String, RateLimitInfo>>> = LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
    
    #[derive(Debug, Clone)]
    struct ExtensionSession {
        #[allow(dead_code)]
        extension_id: String,
        session_token: String,
        #[allow(dead_code)]
        encryption_key: [u8; 32],
        #[allow(dead_code)]
        created_at: Instant,
        #[allow(dead_code)]
        last_activity: Instant,
        #[allow(dead_code)]
        request_count: u32,
        #[allow(dead_code)]
        failed_attempts: u32,
    }
    
    #[allow(dead_code)]
    #[derive(Debug, Clone)]
    struct RateLimitInfo {
        requests: Vec<Instant>,
        last_reset: Instant,
    }
    
    impl ExtensionSession {
        fn new(extension_id: String) -> Self {
            let now = Instant::now();
            let mut encryption_key = [0u8; 32];
            OsRng.fill_bytes(&mut encryption_key);
            
            Self {
                extension_id: extension_id.clone(),
                session_token: generate_session_token(),
                encryption_key,
                created_at: now,
                last_activity: now,
                request_count: 0,
                failed_attempts: 0,
            }
        }
        
        #[allow(dead_code)]
        fn is_valid(&self) -> bool {
            // Session expires after 1 hour of inactivity or if too many failed attempts
            self.last_activity.elapsed() < Duration::from_secs(3600) && self.failed_attempts < 5
        }
        
        #[allow(dead_code)]
        fn update_activity(&mut self) {
            self.last_activity = Instant::now();
            self.request_count += 1;
        }
        
        #[allow(dead_code)]
        fn record_failed_attempt(&mut self) {
            self.failed_attempts += 1;
            self.last_activity = Instant::now();
        }
        
        #[allow(dead_code)]
        fn reset_failed_attempts(&mut self) {
            self.failed_attempts = 0;
        }
    }

    fn find_session_by_token(token: &str) -> Option<ExtensionSession> {
        if let Ok(sessions) = EXTENSION_SESSIONS.lock() {
            for (_ext_id, session) in sessions.iter() {
                if session.session_token == token {
                    return Some(session.clone());
                }
            }
        }
        None
    }
    
    fn generate_session_token() -> String {
        let mut token = [0u8; 32];
        OsRng.fill_bytes(&mut token);
        BASE64.encode(token)
    }
    
    // Rate limiting functions
    #[allow(dead_code)]
    fn check_rate_limit(extension_id: &str) -> bool {
        const MAX_REQUESTS_PER_MINUTE: usize = 60;
        const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
        
        if let Ok(mut rate_limiter) = RATE_LIMITER.lock() {
            let now = Instant::now();
            let rate_info = rate_limiter.entry(extension_id.to_string()).or_insert(RateLimitInfo {
                requests: Vec::new(),
                last_reset: now,
            });
            
            // Remove old requests outside the window
            rate_info.requests.retain(|&request_time| now.duration_since(request_time) < RATE_LIMIT_WINDOW);
            
            // Check if we're under the limit
            if rate_info.requests.len() < MAX_REQUESTS_PER_MINUTE {
                rate_info.requests.push(now);
                true
            } else {
                false
            }
        } else {
            // If we can't acquire the lock, allow the request (fail open)
            true
        }
    }
    
    // Simple encryption/decryption using ChaCha20Poly1305
    #[allow(dead_code)]
    fn encrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace, Nonce};
        
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let mut buffer = data.to_vec();
        cipher.encrypt_in_place(nonce, b"", &mut buffer)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        // Prepend nonce to encrypted data
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&buffer);
        Ok(result)
    }
    
    #[allow(dead_code)]
    fn decrypt_data(encrypted_data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace, Nonce};
        
        if encrypted_data.len() < 12 {
            return Err("Invalid encrypted data".to_string());
        }
        
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let mut buffer = ciphertext.to_vec();
        cipher.decrypt_in_place(nonce, b"", &mut buffer)
            .map_err(|e| format!("Decryption failed: {}", e))?;
        
        Ok(buffer)
    }
    
    // Session validation with security checks
    #[allow(dead_code)]
    fn validate_session(session_token: &str, extension_id: &str) -> Result<bool, String> {
        if !check_rate_limit(extension_id) {
            return Err("Rate limit exceeded".to_string());
        }
        
        if let Ok(mut sessions) = EXTENSION_SESSIONS.lock() {
            if let Some(session) = sessions.get_mut(extension_id) {
                if session.session_token == session_token && session.is_valid() {
                    session.update_activity();
                    session.reset_failed_attempts();
                    Ok(true)
                } else {
                    session.record_failed_attempt();
                    Ok(false)
                }
            } else {
                Ok(false)
            }
        } else {
            Err("Unable to validate session".to_string())
        }
    }
    
    fn generate_password_with_options(options: &PasswordGenerationOptions) -> Result<String, String> {
        if options.length == 0 {
            return Err("Password length must be greater than 0".to_string());
        }
        
        if options.length > 128 {
            return Err("Password length cannot exceed 128 characters".to_string());
        }
        
        let mut charset = String::new();
        
        if options.include_uppercase {
            charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }
        if options.include_lowercase {
            charset.push_str("abcdefghijklmnopqrstuvwxyz");
        }
        if options.include_numbers {
            charset.push_str("0123456789");
        }
        if options.include_symbols {
            charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?");
        }
        
        if charset.is_empty() {
            return Err("At least one character type must be selected".to_string());
        }
        
        let charset_bytes = charset.as_bytes();
        let mut password = String::with_capacity(options.length);
        let mut rng_bytes = vec![0u8; options.length];
        
        OsRng.fill_bytes(&mut rng_bytes);
        
        for &byte in &rng_bytes {
            let index = (byte as usize) % charset_bytes.len();
            password.push(charset_bytes[index] as char);
        }
        
        Ok(password)
    }
    
    // Native messaging protocol implementation
    pub fn read_message<R: Read>(mut input: R) -> io::Result<serde_json::Value> {
        // Read the 4-byte length prefix
        let length = input.read_u32::<NativeEndian>()?;
        
        // Validate message size (max 1MB from extension to host)
        if length > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Message too large"
            ));
        }
        
        // Read the JSON message
        let mut buffer = vec![0u8; length as usize];
        input.read_exact(&mut buffer)?;
        
        // Parse JSON
        let json_val: serde_json::Value = serde_json::from_slice(&buffer)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        
        Ok(json_val)
    }
    
    pub fn write_message<W: Write>(mut output: W, value: &serde_json::Value) -> io::Result<()> {
        let msg = serde_json::to_string(value)?;
        let len = msg.len();
        
        // Chrome won't accept a message larger than 1MB
        if len > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Message too large"
            ));
        }
        
        // Write length prefix and message
        output.write_u32::<NativeEndian>(len as u32)?;
        output.write_all(msg.as_bytes())?;
        output.flush()?;
        
        Ok(())
    }
    
    // Validate extension ID against allowed list
    fn is_extension_authorized(extension_id: &str) -> bool {
        // Whitelist of authorized extension IDs (plain IDs without protocol)
        #[allow(dead_code)]
        const AUTHORIZED_EXTENSIONS: &[&str] = &[
            // Add your actual extension IDs here
            // "abcdefghijklmnopqrstuvwxyz123456",
            // "12345678-1234-1234-1234-123456789abc",
        ];
        
        // For development, allow any extension with proper format
        // Extension ID should be 32 characters long for Chrome extensions
        let has_valid_format = extension_id.len() == 32 && 
                              extension_id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        
        // Production check (uncomment for production use):
        // AUTHORIZED_EXTENSIONS.contains(&extension_id)
        
        // Development check:
        has_valid_format
    }
    
    // Validate origin domain with enhanced security
    fn is_origin_valid(origin: &str) -> bool {
        // Allow chrome-extension origins (browser extensions)
        if origin.starts_with("chrome-extension://") {
            // Validate chrome extension ID format (32 characters, lowercase letters)
            if let Some(extension_id) = origin.strip_prefix("chrome-extension://") {
                return extension_id.len() == 32 && 
                       extension_id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
            }
        }
        
        // Allowed origins for development and production
        const ALLOWED_ORIGINS: &[&str] = &[
            "https://localhost",
            "http://localhost",
            "https://127.0.0.1",
            "http://127.0.0.1",
            // Add your production domains here
            // "https://yourdomain.com",
        ];
        
        // Check against whitelist
        if ALLOWED_ORIGINS.iter().any(|&allowed| origin.starts_with(allowed)) {
            return true;
        }
        
        // Additional validation for HTTPS origins
        if origin.starts_with("https://") {
            // Parse URL to validate structure
            if let Ok(url) = url::Url::parse(origin) {
                // Check for valid host
                if let Some(host) = url.host_str() {
                    // Reject suspicious patterns
                    return !host.contains("..") && 
                           !host.starts_with('.') && 
                           !host.ends_with('.') &&
                           host.len() < 253; // RFC limit
                }
            }
        }
        
        false
    }
    
    // Additional security validation
    fn validate_message_integrity(message: &serde_json::Value) -> bool {
        // Check for required fields and validate structure
        if let Some(msg_type) = message.get("type") {
            if let Some(type_str) = msg_type.as_str() {
                match type_str {
                    "Authenticate" => {
                        message.get("extension_id").is_some() && 
                        message.get("origin").is_some()
                    },
                    "SearchCredentials" => {
                        message.get("domain").is_some()
                    },
                    "SearchCredentialsWithPassword" => {
                        message.get("domain").is_some() && 
                        message.get("master_password").is_some()
                    },
                    "VerifyTotp" => {
                        message.get("code").is_some()
                    },
                    "SaveCredential" => {
                        // Accept either flat fields or nested credentials object
                        if let Some(creds) = message.get("credentials") {
                            creds.get("domain").is_some() &&
                            creds.get("username").is_some() &&
                            creds.get("password").is_some()
                        } else {
                            message.get("domain").is_some() && 
                            message.get("username").is_some() && 
                            message.get("password").is_some()
                        }
                    },
                    "GeneratePassword" => {
                        // Check if options object exists and has valid structure
                        if let Some(options) = message.get("options") {
                            if let Some(length) = options.get("length") {
                                if let Some(len_num) = length.as_u64() {
                                    len_num > 0 && len_num <= 128
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    },
                    "GetPassword" => {
                        message.get("credential_id").is_some() &&
                        message.get("session_token").is_some()
                    },
                    "UnlockVault" => message.get("master_password").is_some(),
                    "GetVaultStatus" => true,
                    "UnlockWithDeviceKey" => true,
                    "EnableDeviceUnlock" => true,
                    _ => false
                }
            } else {
                false
            }
        } else {
            false
        }
    }
    
    // Main message handler
    pub async fn handle_extension_message(
        message: ExtensionMessage,
        app_handle: &AppHandle,
    ) -> ExtensionResponse {
        match message {
            ExtensionMessage::Authenticate { extension_id, origin } => {
                if !is_extension_authorized(&extension_id) {
                    return ExtensionResponse::AuthenticationResult {
                        success: false,
                        session_token: None,
                        encryption_key: None,
                        error: Some("Extension not authorized".to_string()),
                    };
                }
                
                if !is_origin_valid(&origin) {
                    return ExtensionResponse::AuthenticationResult {
                        success: false,
                        session_token: None,
                        encryption_key: None,
                        error: Some("Invalid origin".to_string()),
                    };
                }
                
                // Create new session
                let session = ExtensionSession::new(extension_id.clone());
                let session_token = session.session_token.clone();
                let encryption_key_b64 = BASE64.encode(session.encryption_key);
                
                if let Ok(mut sessions) = EXTENSION_SESSIONS.lock() {
                    sessions.insert(extension_id, session);
                }
                
                ExtensionResponse::AuthenticationResult {
                    success: true,
                    session_token: Some(session_token),
                    encryption_key: Some(encryption_key_b64),
                    error: None,
                }
            }
            
            ExtensionMessage::GetVaultStatus => {
                let vault_path = get_vault_path(app_handle).unwrap_or_else(|_| PathBuf::new());
                let vault_exists = vault_path.exists();
                let is_unlocked = {
                    if let Ok(state) = lock_vault_state(&app_handle.state()) {
                        !state.is_locked
                    } else {
                        false
                    }
                };
                
                ExtensionResponse::VaultStatusResult {
                    is_unlocked,
                    vault_exists,
                }
            }

            ExtensionMessage::UnlockWithDeviceKey => {
                // Attempt to unlock using DPAPI-protected master key
                let app_state = app_handle.state::<AppState>();
                let device_key_path = match get_device_unlock_key_path(app_handle) {
                    Ok(p) => p,
                    Err(e) => {
                        return ExtensionResponse::UnlockResult { success: false, error: Some(e.to_string()) };
                    }
                };
                if !device_key_path.exists() {
                    return ExtensionResponse::UnlockResult { success: false, error: Some("Device unlock not enabled".to_string()) };
                }
                let protected = match fs::read(&device_key_path) {
                    Ok(b) => b,
                    Err(e) => {
                        return ExtensionResponse::UnlockResult { success: false, error: Some(format!("Failed to read device key: {}", e)) };
                    }
                };
                let master_key_bytes = match dpapi_unprotect(&protected) {
                    Ok(b) => b,
                    Err(_) => {
                        return ExtensionResponse::UnlockResult { success: false, error: Some("Failed to unprotect device key".to_string()) };
                    }
                };
                if master_key_bytes.len() != 32 {
                    return ExtensionResponse::UnlockResult { success: false, error: Some("Invalid device key length".to_string()) };
                }
                let mut mk_arr = [0u8; 32];
                mk_arr.copy_from_slice(&master_key_bytes);
                let master_key = SecureKey::new(mk_arr);

                // Read vault and verify/decrypt using master key
                let vault_path = match get_vault_path(app_handle) {
                    Ok(p) => p,
                    Err(e) => {
                        return ExtensionResponse::UnlockResult { success: false, error: Some(e.to_string()) };
                    }
                };
                if !vault_path.exists() {
                    return ExtensionResponse::UnlockResult { success: false, error: Some("Vault not found".to_string()) };
                }
                let contents = match fs::read_to_string(&vault_path) {
                    Ok(c) => c,
                    Err(e) => {
                        return ExtensionResponse::UnlockResult { success: false, error: Some(format!("Failed to read vault: {}", e)) };
                    }
                };
                let encrypted_vault: EncryptedVault = match serde_json::from_str(&contents) {
                    Ok(v) => v,
                    Err(e) => {
                        return ExtensionResponse::UnlockResult { success: false, error: Some(format!("Vault JSON corrupted: {}", e)) };
                    }
                };
                if encrypted_vault.version > VAULT_VERSION {
                    return ExtensionResponse::UnlockResult { success: false, error: Some("Vault version is newer than supported".to_string()) };
                }
                let salt = match BASE64.decode(encrypted_vault.salt) { Ok(s) => s, Err(e) => return ExtensionResponse::UnlockResult { success: false, error: Some(e.to_string()) } };
                let stored_verifier = match BASE64.decode(encrypted_vault.verifier) { Ok(v) => v, Err(e) => return ExtensionResponse::UnlockResult { success: false, error: Some(e.to_string()) } };
                match verify_master_key(&master_key, &salt, &stored_verifier) {
                    Ok(true) => {}
                    Ok(false) => {
                        return ExtensionResponse::UnlockResult { success: false, error: Some("Device key does not match vault".to_string()) };
                    }
                    Err(e) => {
                        return ExtensionResponse::UnlockResult { success: false, error: Some(e.to_string()) };
                    }
                }
                let (encryption_key, _) = match derive_keys(&master_key, &salt) {
                    Ok(pair) => pair,
                    Err(e) => return ExtensionResponse::UnlockResult { success: false, error: Some(e.to_string()) },
                };
                let encrypted_data = match BASE64.decode(encrypted_vault.data) { Ok(d) => d, Err(e) => return ExtensionResponse::UnlockResult { success: false, error: Some(e.to_string()) } };
                let nonce = match BASE64.decode(encrypted_vault.nonce) { Ok(n) => n, Err(e) => return ExtensionResponse::UnlockResult { success: false, error: Some(e.to_string()) } };
                let aad = match BASE64.decode(encrypted_vault.aad) { Ok(a) => a, Err(e) => return ExtensionResponse::UnlockResult { success: false, error: Some(e.to_string()) } };
                let decrypted = match decrypt_with_aad(&encrypted_data, &encryption_key, &nonce, &aad) {
                    Ok(p) => p,
                    Err(_) => return ExtensionResponse::UnlockResult { success: false, error: Some("Failed to decrypt vault data".to_string()) },
                };
                let payload: VaultPayload = match serde_json::from_slice::<VaultPayload>(&decrypted) {
                    Ok(p) => p,
                    Err(_) => {
                        // Backwards compat: entries-only payload
                        match serde_json::from_slice::<Vec<PasswordEntry>>(&decrypted) {
                            Ok(entries) => VaultPayload { entries, totp_account: None },
                            Err(e) => return ExtensionResponse::UnlockResult { success: false, error: Some(e.to_string()) },
                        }
                    }
                };
                // Set master key and unlock state
                if let Ok(mut mk) = lock_master_key(&app_state) {
                    *mk = Some(master_key);
                }
                if let Err(err) = write_audit_log(app_handle, "vault_unlock", "Vault unlocked via device key") {
                    eprintln!("AUDIT WRITE ERROR: {}", err);
                }
                if let Ok(mut state) = lock_vault_state(&app_state) {
                    state.entries = payload.entries.clone();
                    state.totp_account = payload.totp_account.clone();
                    update_activity(&mut state);
                    state.is_locked = false;
                }
                ExtensionResponse::UnlockResult { success: true, error: None }
            }
            
            ExtensionMessage::GetPassword { credential_id, session_token } => {
                // Check if vault is unlocked and update activity
                if let Ok(mut state) = lock_vault_state(&app_handle.state()) {
                    if state.is_locked {
                        return ExtensionResponse::UnlockRequired {
                            message: "Please enter your master password to retrieve the password".to_string(),
                        };
                    }
                    // Keep session alive while serving extension
                    update_activity(&mut state);

                    if let Some(entry) = state.entries.iter().find(|e| e.id == credential_id) {
                        // Encrypt password using session AES-GCM key
                        if let Some(session) = find_session_by_token(&session_token) {
                                let cipher = Aes256Gcm::new_from_slice(&session.encryption_key).unwrap();
                                let mut nonce_bytes = [0u8; 12];
                                OsRng.fill_bytes(&mut nonce_bytes);
                                let nonce = Nonce::from_slice(&nonce_bytes);
                                match cipher.encrypt(nonce, entry.password.as_bytes()) {
                                    Ok(ct) => ExtensionResponse::PasswordResult {
                                        success: true,
                                        password: None,
                                        encrypted_password: Some(BASE64.encode(ct)),
                                        nonce: Some(BASE64.encode(nonce_bytes)),
                                        error: None,
                                    },
                                    Err(_) => ExtensionResponse::PasswordResult {
                                        success: false,
                                        password: None,
                                        encrypted_password: None,
                                        nonce: None,
                                        error: Some("Encryption failed".to_string()),
                                    },
                                }
                            } else {
                                ExtensionResponse::PasswordResult {
                                    success: false,
                                    password: None,
                                    encrypted_password: None,
                                    nonce: None,
                                    error: Some("Invalid session".to_string()),
                                }
                            }
                    } else {
                        ExtensionResponse::PasswordResult {
                            success: false,
                            password: None,
                            encrypted_password: None,
                            nonce: None,
                            error: Some("Credential not found".to_string()),
                        }
                    }
                } else {
                    ExtensionResponse::PasswordResult {
                        success: false,
                        password: None,
                        encrypted_password: None,
                        nonce: None,
                        error: Some("Unable to check vault state".to_string()),
                    }
                }
            }
            
            ExtensionMessage::UnlockVault { master_password } => {
                match unlock_vault(master_password, app_handle.state(), app_handle.clone()).await {
                    Ok(_) => ExtensionResponse::UnlockResult {
                        success: true,
                        error: None,
                    },
                    Err(e) => ExtensionResponse::UnlockResult {
                        success: false,
                        error: Some(e),
                    },
                }
            }

            ExtensionMessage::EnableDeviceUnlock => {
                // Persist the current master key using DPAPI for device unlock
                let app_state = app_handle.state::<AppState>();
                let current_mk = match lock_master_key(&app_state) {
                    Ok(guard) => guard.clone(),
                    Err(_) => None,
                };
                if current_mk.is_none() {
                    return ExtensionResponse::UnlockResult { success: false, error: Some("Vault is locked; cannot enable device unlock".to_string()) };
                }
                let key = current_mk.unwrap();
                let protected = match dpapi_protect(key.expose()) {
                    Ok(p) => p,
                    Err(_) => return ExtensionResponse::UnlockResult { success: false, error: Some("Failed to protect device key".to_string()) },
                };
                let device_key_path = match get_device_unlock_key_path(app_handle) {
                    Ok(p) => p,
                    Err(e) => return ExtensionResponse::UnlockResult { success: false, error: Some(e.to_string()) },
                };
                if let Some(parent) = device_key_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match fs::write(&device_key_path, protected) {
                    Ok(_) => {
                        if let Err(err) = write_audit_log(app_handle, "device_unlock_enabled", "Stored DPAPI-protected master key") {
                            eprintln!("AUDIT WRITE ERROR: {}", err);
                        }
                        ExtensionResponse::UnlockResult { success: true, error: None }
                    }
                    Err(e) => ExtensionResponse::UnlockResult { success: false, error: Some(format!("Failed to write device key: {}", e)) },
                }
            }
            
            ExtensionMessage::SearchCredentials { domain, url: _ } => {
                // Check if vault is unlocked and update activity
                if let Ok(mut state) = lock_vault_state(&app_handle.state()) {
                    if state.is_locked {
                        return ExtensionResponse::UnlockRequired {
                            message: format!("Please enter your master password to search for credentials for {}", domain),
                        };
                    }
                    // Update activity to prevent auto-lock during extension use
                    update_activity(&mut state);
                } else {
                    return ExtensionResponse::CredentialsResult {
                        success: false,
                        credentials: None,
                        error: Some("Unable to check vault state".to_string()),
                    };
                }
                
                // Search for credentials matching the domain
                match search_credentials_by_domain(&domain, app_handle) {
                    Ok(credentials) => ExtensionResponse::CredentialsResult {
                        success: true,
                        credentials: Some(credentials),
                        error: None,
                    },
                    Err(e) => ExtensionResponse::CredentialsResult {
                        success: false,
                        credentials: None,
                        error: Some(e),
                    },
                }
            }
            
            ExtensionMessage::SearchCredentialsWithPassword { domain, url: _, master_password } => {
                eprintln!("=== SearchCredentialsWithPassword START ===");
                eprintln!("Domain: {}", domain);
                eprintln!("Master password length: {}", master_password.len());
                
                // First, try to unlock the vault with the provided password
                // As requested for reduced interaction in browser extension flows,
                // bypass MFA by marking it as recently verified before unlocking.
                // This only affects native messaging path and does not change desktop UI behavior.
                {
                    let _ = lock_mfa_time(&app_handle.state()).map(|mut mfa| {
                        *mfa = Some(std::time::Instant::now());
                    });
                }
                eprintln!("Attempting to unlock vault...");
                match unlock_vault(master_password, app_handle.state(), app_handle.clone()).await {
                    Ok(_) => {
                        eprintln!("Vault unlocked successfully");
                        // Vault unlocked successfully, now search for credentials
                        eprintln!("Searching for credentials for domain: {}", domain);
                        match search_credentials_by_domain(&domain, app_handle) {
                            Ok(credentials) => {
                                eprintln!("Credential search completed successfully. Found {} credentials", credentials.len());
                                eprintln!("=== SearchCredentialsWithPassword SUCCESS ===");
                                ExtensionResponse::CredentialsResult {
                                    success: true,
                                    credentials: Some(credentials),
                                    error: None,
                                }
                            },
                            Err(e) => {
                                eprintln!("Credential search failed: {}", e);
                                eprintln!("=== SearchCredentialsWithPassword SEARCH_ERROR ===");
                                ExtensionResponse::CredentialsResult {
                                    success: false,
                                    credentials: None,
                                    error: Some(e),
                                }
                            },
                        }
                    },
                    Err(e) => {
                        eprintln!("Vault unlock failed: {}", e);
                        eprintln!("=== SearchCredentialsWithPassword UNLOCK_ERROR ===");
                        ExtensionResponse::CredentialsResult {
                            success: false,
                            credentials: None,
                            error: Some(format!("Failed to unlock vault: {}", e)),
                        }
                    },
                }
            }
            
            ExtensionMessage::VerifyTotp { code } => {
                eprintln!("=== VerifyTotp START ===");
                match verify_totp(code, None, app_handle.state(), app_handle.clone()).await {
                    Ok(ok) => {
                        eprintln!("VerifyTotp result: {}", ok);
                        ExtensionResponse::TotpResult {
                            success: ok,
                            error: None,
                        }
                    },
                    Err(e) => {
                        eprintln!("VerifyTotp error: {}", e);
                        ExtensionResponse::TotpResult {
                            success: false,
                            error: Some(e),
                        }
                    }
                }
            }
            
            ExtensionMessage::GeneratePassword { options } => {
                match generate_password_with_options(&options) {
                    Ok(password) => ExtensionResponse::PasswordResult {
                        success: true,
                        password: Some(password),
                        encrypted_password: None,
                        nonce: None,
                        error: None,
                    },
                    Err(e) => ExtensionResponse::PasswordResult {
                        success: false,
                        password: None,
                        encrypted_password: None,
                        nonce: None,
                        error: Some(e.to_string()),
                    },
                }
            }
            
            ExtensionMessage::SaveCredential { domain, username, password, url } => {
                // Create entry data in the format expected by add_entry
                let entry_data = serde_json::json!({
                    "service": domain,
                    "username": username,
                    "password": password,
                    "url": url,
                    "notes": null
                });
                
                // Use the existing add_entry function
                match add_entry(entry_data, app_handle.state(), app_handle.clone()).await {
                    Ok(_) => ExtensionResponse::SaveResult {
                        success: true,
                        error: None,
                    },
                    Err(e) => ExtensionResponse::SaveResult {
                        success: false,
                        error: Some(e),
                    },
                }
            }
        }
    }
    
    // Helper function to search credentials by domain
    fn search_credentials_by_domain(
        domain: &str,
        app_handle: &AppHandle,
    ) -> Result<Vec<CredentialMatch>, String> {
        let app_state = app_handle.state();
        let mut vault = lock_vault_state(&app_state).map_err(|e| e.to_string())?;
        
        // Check if vault is locked
        if vault.is_locked {
            return Err("Vault is locked".to_string());
        }
        
        // Update activity to prevent auto-lock during active use
        update_activity(&mut vault);
        
        let mut matches = Vec::new();
        
        for entry in &vault.entries {
            // Check if the domain matches the entry's URL or service name
            let domain_matches = if let Some(url) = &entry.url {
                extract_domain(url).map_or(false, |stored_domain| {
                    domains_match(domain, &stored_domain)
                })
            } else {
                // For entries without URLs, check service name
                domains_match(domain, &entry.service)
            };
            
            if domain_matches {
                matches.push(CredentialMatch {
                    id: entry.id.clone(),
                    username: entry.username.clone(),
                    domain: extract_domain(entry.url.as_deref().unwrap_or(&entry.service))
                        .unwrap_or_else(|| entry.service.clone()),
                    url: entry.url.clone().unwrap_or_else(|| entry.service.clone()),
                    last_used: None, // PasswordEntry doesn't have last_used field in this codebase
                });
            }
        }
        
        Ok(matches)
    }

    // Enhanced domain matching function
    fn domains_match(search_domain: &str, stored_domain: &str) -> bool {
        let search_lower = search_domain.to_lowercase();
        let stored_lower = stored_domain.to_lowercase();
        
        // Exact match
        if search_lower == stored_lower {
            return true;
        }
        
        // Simple substring match (existing behavior)
        if search_lower.contains(&stored_lower) || stored_lower.contains(&search_lower) {
            return true;
        }
        
        // Enhanced institutional domain matching
        // Extract the main domain parts (e.g., "unitbv.ro" from "student.unitbv.ro")
        let search_parts = extract_domain_parts(&search_lower);
        let stored_parts = extract_domain_parts(&stored_lower);
        
        // Check if the main domain parts match
        if search_parts.len() >= 2 && stored_parts.len() >= 2 {
            let search_main = format!("{}.{}", 
                search_parts[search_parts.len() - 2], 
                search_parts[search_parts.len() - 1]
            );
            let stored_main = format!("{}.{}", 
                stored_parts[stored_parts.len() - 2], 
                stored_parts[stored_parts.len() - 1]
            );
            
            if search_main == stored_main {
                return true;
            }
        }
        
        // Check if one is a subdomain of the other
        if search_lower.ends_with(&format!(".{}", stored_lower)) || 
           stored_lower.ends_with(&format!(".{}", search_lower)) {
            return true;
        }
        
        false
    }
    
    // Helper function to split domain into parts
    fn extract_domain_parts(domain: &str) -> Vec<&str> {
        domain.split('.').collect()
    }
    
    // Helper function to extract domain from URL
    fn extract_domain(url: &str) -> Option<String> {
        if let Ok(parsed_url) = url::Url::parse(url) {
            parsed_url.host_str().map(|h| h.to_string())
        } else {
            // If URL parsing fails, try to extract domain manually
            let cleaned = url.trim_start_matches("http://")
                .trim_start_matches("https://")
                .trim_start_matches("www.");
            
            if let Some(slash_pos) = cleaned.find('/') {
                Some(cleaned[..slash_pos].to_string())
            } else {
                Some(cleaned.to_string())
            }
        }
    }
    
    // Native messaging host entry point
    pub async fn run_native_messaging_host(app_handle: AppHandle) -> io::Result<()> {
        let stdin = io::stdin();
        let stdout = io::stdout();
        
        // Initialize security logging
        eprintln!("=== NATIVE MESSAGING HOST STARTED ===");
        eprintln!("Process ID: {}", std::process::id());
        eprintln!("Arguments: {:?}", std::env::args().collect::<Vec<String>>());
        eprintln!("Native messaging host started with enhanced security");
        
        loop {
            // Read message from extension
            match read_message(stdin.lock()) {
                Ok(json_message) => {
                    // Validate message integrity first
                    if !validate_message_integrity(&json_message) {
                        eprintln!("Message integrity validation failed");
                        let mut error_response = serde_json::json!({
                            "type": "error",
                            "message": "Message integrity validation failed"
                        });
                        // Preserve message ID for error responses too
                        if let Some(id) = json_message.get("id") {
                            error_response["id"] = id.clone();
                        }
                        let _ = write_message(stdout.lock(), &error_response);
                        continue;
                    }
                    
                    // Parse the message
                    match serde_json::from_value::<ExtensionMessage>(json_message.clone()) {
                        Ok(message) => {
                            // Log the message type for security auditing
                            if let Some(msg_type) = json_message.get("type") {
                                eprintln!("Processing message type: {}", msg_type);
                                if let Some(id) = json_message.get("id") {
                                    eprintln!("Message ID: {}", id);
                                }
                            }
                            
                            // Handle the message with enhanced security
                            eprintln!("Starting message handler...");
                            let start_time = std::time::Instant::now();
                            let response = handle_extension_message(message, &app_handle).await;
                            let duration = start_time.elapsed();
                            eprintln!("Message handler completed in {:?}", duration);
                            
                            // Send response back to extension with preserved message ID
                            if let Ok(mut response_json) = serde_json::to_value(&response) {
                                // Preserve the message ID from the original request
                                if let Some(id) = json_message.get("id") {
                                    response_json["id"] = id.clone();
                                }
                                
                                if let Err(e) = write_message(stdout.lock(), &response_json) {
                                    eprintln!("Failed to write response: {}", e);
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to parse message: {}", e);
                            // Send error response
                            let mut error_response = serde_json::json!({
                                "type": "error",
                                "message": format!("Invalid message format: {}", e)
                            });
                            // Preserve message ID for error responses too
                            if let Some(id) = json_message.get("id") {
                                error_response["id"] = id.clone();
                            }
                            let _ = write_message(stdout.lock(), &error_response);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read message: {}", e);
                    break;
                }
            }
        }
        
        eprintln!("Native messaging host shutting down");
        Ok(())
    }
}
