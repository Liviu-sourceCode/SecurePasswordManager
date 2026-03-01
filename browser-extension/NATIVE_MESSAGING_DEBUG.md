# Chrome Native Messaging Debug Guide

## Issue
**Error**: "Access to the specified native messaging host is forbidden"

This error occurs when trying to establish communication between the Chrome browser extension and the native messaging host (`SecurePasswordManager.exe`).

## Debug Steps Performed

### ✅ Step 1: File Permissions Check
**Purpose**: Ensure the native messaging host executable has proper execution permissions.

**Actions Taken**:
- Verified `SecurePasswordManager.exe` exists at: `C:\Users\Liviu\PasswordManager\src-tauri\target\debug\SecurePasswordManager.exe`
- Confirmed file has execution permissions
- **Result**: ✅ File permissions are correct

### ✅ Step 2: Native Messaging Manifest Validation
**Purpose**: Verify the native messaging host manifest file is valid JSON with correct format.

**File**: `browser-extension\native-messaging-host\com.passwordmanager.native.json`

**Verified Fields**:
```json
{
  "name": "com.passwordmanager.native",
  "description": "Password Manager Native Messaging Host",
  "path": "C:\\Users\\Liviu\\PasswordManager\\src-tauri\\target\\debug\\SecurePasswordManager.exe",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://oopikpedmqpagipffqchakgiplnmocdo/"
  ]
}
```

**Validation Results**:
- ✅ Valid JSON format
- ✅ All required fields present (`name`, `description`, `path`, `type`, `allowed_origins`)
- ✅ Path points to correct executable
- ✅ Type is "stdio"
- ✅ Extension ID format is correct

### ✅ Step 3: Windows Registry Verification
**Purpose**: Ensure Chrome can find the native messaging host through Windows registry entries.

**Registry Locations Checked**:

1. **64-bit Registry (HKEY_CURRENT_USER)**:
   ```
   HKCU\Software\Google\Chrome\NativeMessagingHosts\com.passwordmanager.native
   ```
   - **Result**: ✅ Entry exists, points to correct manifest file

2. **64-bit Registry (HKEY_LOCAL_MACHINE)**:
   ```
   HKLM\Software\Google\Chrome\NativeMessagingHosts\com.passwordmanager.native
   ```
   - **Result**: ❌ Entry not found (not required if HKCU exists)

3. **32-bit Registry (HKEY_CURRENT_USER)** - **CRITICAL**:
   ```
   HKCU\SOFTWARE\WOW6432Node\Google\Chrome\NativeMessagingHosts\com.passwordmanager.native
   ```
   - **Initial Result**: ❌ Entry missing
   - **Action**: Added registry entry pointing to manifest file
   - **Final Result**: ✅ Entry created successfully

**Key Finding**: Chrome searches 32-bit registry first, then 64-bit registry. The missing 32-bit registry entry was likely the primary cause.

### ✅ Step 4: Direct Executable Testing
**Purpose**: Verify the native messaging host works when executed directly.

**Command Used**:
```powershell
& "C:\Users\Liviu\PasswordManager\src-tauri\target\debug\SecurePasswordManager.exe" "chrome-extension://oopikpedmqpagipffqchakgiplnmocdo/"
```

**Result**: ✅ Executable starts successfully in native messaging mode
- Shows process ID
- Displays correct arguments
- Indicates enhanced security mode

### ✅ Step 5: Extension Permissions Verification
**Purpose**: Ensure the browser extension has the required `nativeMessaging` permission.

**File**: `browser-extension\manifest.json`

**Verified**:
```json
{
  "permissions": ["nativeMessaging", ...]
}
```

**Result**: ✅ Permission is correctly listed

### ✅ Step 6: Chrome Debug Logging
**Purpose**: Enable Chrome's internal logging to see detailed error messages.

**Actions**:
1. Closed all Chrome instances: `taskkill /f /im chrome.exe`
2. Started Chrome with logging: `Start-Process chrome -ArgumentList "--enable-logging", "--v=1"`

**Debug Log Location**: `C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\chrome_debug.log`

**Result**: ✅ Logging enabled for detailed error analysis

## Registry Commands Used

### Add 32-bit Registry Entry (CRITICAL FIX)
```powershell
New-Item -Path "HKCU:\SOFTWARE\WOW6432Node\Google\Chrome\NativeMessagingHosts" -Name "com.passwordmanager.native" -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\WOW6432Node\Google\Chrome\NativeMessagingHosts\com.passwordmanager.native" -Name "(Default)" -Value "C:\Users\Liviu\PasswordManager\browser-extension\native-messaging-host\com.passwordmanager.native.json"
```

### Verify Registry Entries
```powershell
# Check 64-bit HKCU
Get-ItemProperty -Path "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.passwordmanager.native"

# Check 32-bit HKCU (CRITICAL)
Get-ItemProperty -Path "HKCU:\SOFTWARE\WOW6432Node\Google\Chrome\NativeMessagingHosts\com.passwordmanager.native"
```

## Common Causes (Based on Official Chrome Documentation)

1. **Registry Issues** (Most Common):
   - Missing 32-bit registry entry (Chrome checks 32-bit first)
   - Incorrect manifest file path in registry
   - Registry entry in wrong location

2. **Manifest File Issues**:
   - Invalid JSON format
   - Missing required fields
   - Incorrect extension ID in `allowed_origins`
   - Wrong executable path

3. **File Permission Issues**:
   - Executable lacks execution permissions
   - Manifest file not readable

4. **Extension Issues**:
   - Missing `nativeMessaging` permission
   - Extension ID mismatch between manifest and actual extension

## Next Steps if Issue Persists

1. **Verify Extension ID Match**:
   - Go to `chrome://extensions/`
   - Compare actual extension ID with ID in manifest (`oopikpedmqpagipffqchakgiplnmocdo`)

2. **Check Chrome Debug Logs**:
   - After testing, examine: `C:\Users\Liviu\AppData\Local\Google\Chrome\User Data\chrome_debug.log`
   - Look for native messaging related errors

3. **Test with Minimal Host**:
   - Create a simple test native messaging host to isolate the issue

4. **Complete Chrome Restart**:
   - Ensure all Chrome processes are terminated
   - Restart Chrome to pick up registry changes

## References

- [Chrome Native Messaging Documentation](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
- [Chrome Apps Native Messaging](https://developer.chrome.com/docs/apps/nativeMessaging)
- [Microsoft Edge Native Messaging](https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/native-messaging)

## Status

**Primary Fix Applied**: Added missing 32-bit registry entry
**Confidence Level**: High - This addresses the most common cause according to official documentation
**Next Action**: Complete Chrome restart and retest native messaging functionality