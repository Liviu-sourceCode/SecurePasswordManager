# Password Manager Browser Extension - Comprehensive Testing Guide

## Pre-Testing Setup

### 1. Build and Install Prerequisites

**Build the Tauri Application:**
```powershell
cd src-tauri
cargo build --release
```
✅ **Expected Result:** Executable created at `src-tauri/target/release/SecurePasswordManager.exe`

**Install Native Messaging Host:**
```powershell
# For Chrome/Chromium
New-Item -ItemType Directory -Force -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\NativeMessagingHosts"
Copy-Item "browser-extension\native-messaging-host\com.passwordmanager.native.json" "$env:LOCALAPPDATA\Google\Chrome\User Data\NativeMessagingHosts\"
```

**Load Browser Extension:**
1. Open Chrome → `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked" → Select `browser-extension` folder
4. Note the Extension ID (e.g., `abcdefghijklmnopqrstuvwxyz123456`)

**Update Native Messaging Manifest:**
Edit `$env:LOCALAPPDATA\Google\Chrome\User Data\NativeMessagingHosts\com.passwordmanager.native.json`:
```json
{
  "name": "com.passwordmanager.native",
  "description": "Password Manager Native Messaging Host",
  "path": "C:\\Users\\Liviu\\PasswordManager\\src-tauri\\target\\release\\SecurePasswordManager.exe",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://YOUR_ACTUAL_EXTENSION_ID/"
  ]
}
```

## Testing Scenarios

### Test 1: Basic Connection and Authentication

**Objective:** Verify the extension can connect to the Tauri app

**Steps:**
1. **Start the Password Manager app**
   ```powershell
   cd src-tauri/target/release
   ./SecurePasswordManager.exe
   ```

2. **Create/unlock your vault** in the Tauri app

3. **Open the browser extension popup** (click extension icon)

4. **Check connection status**

**Expected Results:**
- ✅ Connection status shows "Connected"
- ✅ No error messages in popup
- ✅ Browser console shows successful authentication
- ✅ Native app console shows connection established

**Troubleshooting:**
- ❌ "Disconnected" → Check native messaging host installation
- ❌ "Connection Error" → Verify Tauri app is running and vault is unlocked
- ❌ Extension not found → Check extension ID in manifest

---

### Test 2: Password Generation

**Objective:** Test secure password generation functionality

**Steps:**
1. **Open extension popup**
2. **Configure password options:**
   - Length: 16 characters
   - Include uppercase: ✓
   - Include lowercase: ✓
   - Include numbers: ✓
   - Include symbols: ✓
3. **Click "Generate Password"**
4. **Test different configurations:**
   - Length: 8, 32, 64, 128
   - Various character type combinations
5. **Test edge cases:**
   - All options unchecked (should show error)
   - Minimum length (8)
   - Maximum length (128)

**Expected Results:**
- ✅ Password generated successfully
- ✅ Password meets specified criteria
- ✅ Password length matches selection
- ✅ Character types match selections
- ✅ Error shown when no character types selected
- ✅ Click to copy functionality works

**Validation:**
- Check generated password contains only selected character types
- Verify password length is exactly as specified
- Test clipboard functionality

---

### Test 3: Form Detection and Auto-fill

**Objective:** Test automatic form detection and credential filling

**Test Sites:**
- `https://example.com/login` (simple form)
- `https://github.com/login` (real-world example)
- `https://accounts.google.com` (complex form)

**Steps:**
1. **Navigate to a login page**
2. **Open browser console** (F12) to monitor content script activity
3. **Check form detection:**
   - Look for auto-fill buttons near password fields
   - Verify forms are detected in console logs
4. **Test credential search:**
   - Open extension popup
   - Verify domain is detected correctly
   - Check if existing credentials are found

**Expected Results:**
- ✅ Forms detected automatically
- ✅ Auto-fill buttons appear near password fields
- ✅ Domain extracted correctly in popup
- ✅ Content script logs show form analysis
- ✅ No JavaScript errors in console

**Advanced Form Testing:**
- **Single-page applications** (React/Angular apps)
- **Dynamic forms** (forms loaded via AJAX)
- **Multiple forms** on same page
- **Forms without `<form>` tags**
- **Shadow DOM forms**

---

### Test 4: Credential Saving

**Objective:** Test saving new credentials from web forms

**Steps:**
1. **Navigate to a test login page**
2. **Fill out login form manually:**
   - Username: `testuser@example.com`
   - Password: `TestPassword123!`
3. **Submit the form**
4. **Check for save prompt** (should appear automatically)
5. **Verify credential saved:**
   - Open Tauri app
   - Check if credential appears in vault
   - Verify all fields saved correctly

**Expected Results:**
- ✅ Save prompt appears after form submission
- ✅ Credential saved to vault
- ✅ Domain/service name detected correctly
- ✅ Username and password saved accurately
- ✅ No duplicate entries created

**Edge Cases:**
- **Forms with multiple submit buttons**
- **AJAX form submissions**
- **Forms with additional fields** (email, phone, etc.)
- **Forms with auto-generated passwords**

---

### Test 5: Credential Auto-fill

**Objective:** Test automatic filling of saved credentials

**Prerequisites:** Have saved credentials from Test 4

**Steps:**
1. **Navigate to the same login page**
2. **Method 1 - Popup auto-fill:**
   - Open extension popup
   - Click on saved credential
   - Verify form is filled
3. **Method 2 - Content script auto-fill:**
   - Click auto-fill button near password field
   - Select credential from dropdown
4. **Test multiple credentials:**
   - Save multiple accounts for same domain
   - Verify all appear in selection
5. **Test form submission:**
   - Fill credentials
   - Submit form
   - Verify successful login

**Expected Results:**
- ✅ Credentials fill correctly
- ✅ Username and password fields populated
- ✅ Multiple credentials shown when available
- ✅ Form submission works after auto-fill
- ✅ Popup closes after successful fill

**Cross-Domain Testing:**
- Test with subdomains (`login.example.com` vs `www.example.com`)
- Test with different protocols (`http` vs `https`)
- Test with port numbers (`localhost:3000`)

---

### Test 6: Security Features

**Objective:** Test security measures and error handling

**Rate Limiting Test:**
1. **Open browser console**
2. **Send rapid requests** (use console):
   ```javascript
   for(let i = 0; i < 70; i++) {
     chrome.runtime.sendMessage({type: 'generatePassword'});
   }
   ```
3. **Verify rate limiting** kicks in after 60 requests

**Session Management Test:**
1. **Authenticate successfully**
2. **Wait for session timeout** (1 hour or modify timeout for testing)
3. **Try to use extension** after timeout
4. **Verify re-authentication required**

**Origin Validation Test:**
1. **Modify extension ID** in native messaging manifest
2. **Try to use extension**
3. **Verify connection fails**
4. **Restore correct extension ID**

**Expected Results:**
- ✅ Rate limiting prevents excessive requests
- ✅ Sessions expire appropriately
- ✅ Invalid origins rejected
- ✅ Error messages are user-friendly
- ✅ Security events logged properly

---

### Test 7: Error Handling and Edge Cases

**Objective:** Test robustness and error recovery

**Network/Connection Errors:**
1. **Close Tauri app** while extension is open
2. **Try to use extension features**
3. **Restart Tauri app**
4. **Verify extension reconnects**

**Invalid Data Handling:**
1. **Test with malformed URLs**
2. **Test with very long passwords**
3. **Test with special characters in usernames**
4. **Test with empty form fields**

**Browser Compatibility:**
1. **Test in Chrome**
2. **Test in Edge** (Chromium-based)
3. **Test in Firefox** (if manifest V2 compatible)

**Expected Results:**
- ✅ Graceful error messages
- ✅ No crashes or freezes
- ✅ Automatic reconnection when possible
- ✅ Data validation prevents corruption
- ✅ Cross-browser compatibility

---

### Test 8: Performance and Usability

**Objective:** Test user experience and performance

**Performance Metrics:**
1. **Extension startup time** (< 1 second)
2. **Password generation time** (< 500ms)
3. **Form detection time** (< 200ms)
4. **Auto-fill response time** (< 300ms)

**Usability Testing:**
1. **Test with screen readers** (accessibility)
2. **Test keyboard navigation**
3. **Test with different screen sizes**
4. **Test popup responsiveness**

**Memory Usage:**
1. **Monitor extension memory usage**
2. **Test with multiple tabs open**
3. **Check for memory leaks**

**Expected Results:**
- ✅ Fast response times
- ✅ Accessible interface
- ✅ Responsive design
- ✅ Minimal memory footprint
- ✅ No performance degradation over time

---

## Automated Testing Script

Create a test script for repetitive testing:

```javascript
// Console script for basic functionality testing
async function runBasicTests() {
  console.log('🧪 Starting Password Manager Extension Tests...');
  
  // Test 1: Connection Status
  try {
    const status = await chrome.runtime.sendMessage({type: 'getConnectionStatus'});
    console.log('✅ Connection Status:', status);
  } catch (e) {
    console.error('❌ Connection test failed:', e);
  }
  
  // Test 2: Password Generation
  try {
    const password = await chrome.runtime.sendMessage({
      type: 'generatePassword',
      options: { length: 16, include_uppercase: true, include_lowercase: true, include_numbers: true, include_symbols: true }
    });
    console.log('✅ Password Generated:', password.password ? '***' : 'Failed');
  } catch (e) {
    console.error('❌ Password generation failed:', e);
  }
  
  // Test 3: Credential Search
  try {
    const results = await chrome.runtime.sendMessage({
      type: 'searchCredentials',
      domain: window.location.hostname
    });
    console.log('✅ Credential Search:', results);
  } catch (e) {
    console.error('❌ Credential search failed:', e);
  }
  
  console.log('🏁 Basic tests completed');
}

// Run tests
runBasicTests();
```

## Test Results Documentation

Create a test results template:

```markdown
## Test Session: [Date]

**Environment:**
- OS: Windows 11
- Browser: Chrome 120.x
- Extension Version: 1.0.0
- Tauri App Version: 1.0.0

**Test Results:**
- [ ] Basic Connection ✅/❌
- [ ] Password Generation ✅/❌
- [ ] Form Detection ✅/❌
- [ ] Credential Saving ✅/❌
- [ ] Auto-fill ✅/❌
- [ ] Security Features ✅/❌
- [ ] Error Handling ✅/❌
- [ ] Performance ✅/❌

**Issues Found:**
1. [Issue description]
2. [Issue description]

**Notes:**
[Additional observations]
```

## Debugging Tips

**Common Issues and Solutions:**

1. **"Native messaging host not found"**
   - Check manifest file location
   - Verify executable path
   - Confirm extension ID matches

2. **"Connection failed"**
   - Ensure Tauri app is running
   - Check vault is unlocked
   - Verify native messaging permissions

3. **"Form not detected"**
   - Check console for content script errors
   - Verify form has password fields
   - Test with simpler forms first

4. **"Auto-fill not working"**
   - Check if credentials exist for domain
   - Verify form field detection
   - Test manual popup fill first

**Debug Commands:**
```powershell
# Check native messaging host installation
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\NativeMessagingHosts"

# Test executable directly
cd src-tauri/target/release
./SecurePasswordManager.exe

# Monitor extension logs
# Open Chrome DevTools → Extensions → Password Manager → Inspect views: background page
```

This comprehensive testing guide ensures all aspects of the browser extension integration are thoroughly validated before deployment.