# GuardME C++



## About

Introducing GuardME! An advanced cybersecurity application providing real-time protection against malicious websites, malware, and data breaches. This is a completely C++ written program featuring URL analysis, virus scanning, password breach checking, system monitoring, download monitoring and an interactive rule-based chatbot assistant.

---

## Purpose

GuardME C++ is designed to help users protect themselves from common cybersecurity threats:

- **Detect phishing websites** before you visit them
- **Check if your passwords have been leaked** in data breaches
- **Scan files for viruses and malware** using ClamAV
- **Monitor system resources** to detect suspicious activity
- **Analyze suspicious files** for potential threats
- **Get security advice** from Guardi, your friendly security assistant

---

## Versions

GuardME comes in two versions:

| Version | Best For | Requirements |
|---------|----------|--------------|
| **Console** | Servers, cloud, SSH, terminals | libcurl, OpenSSL |
| **GUI** | Desktop computers with display | Qt6, OpenGL, libcurl, OpenSSL |

The **Console version** works in any terminal environment, including cloud platforms like Replit.

The **GUI version** provides a full graphical interface with tabs, buttons, and visual dashboards, but requires a local machine with OpenGL support.

---

## Requirements

### System Requirements

| Requirement | Console | GUI |
|-------------|---------|-----|
| Operating System | Linux, macOS, Windows (WSL) | Linux, macOS |
| C++ Compiler | g++ or clang++ with C++17 support | g++ or clang++ with C++17 support |
| Build Tools | pkg-config | cmake, pkg-config |
| Display | Not required | OpenGL-capable display |
| RAM (Runtime) | 50 MB minimum | 150 MB minimum |
| Disk Space | ~5 MB (binary + dependencies) | ~50 MB (binary + Qt libraries) |
| Disk Space (Build) | ~100 MB | ~500 MB (includes Qt development files) |

### Console Version Dependencies

| Package | Purpose | Required |
|---------|---------|----------|
| libcurl | HTTP requests to external APIs | Yes |
| OpenSSL | SHA-1 hashing for breach checks | Yes |
| ClamAV | Virus scanning with clamscan | Optional |

### GUI Version Dependencies

| Package | Purpose | Required |
|---------|---------|----------|
| Qt6 | Graphical user interface framework | Yes |
| libcurl | HTTP requests to external APIs | Yes |
| OpenSSL | Cryptographic functions (AES, SHA, PBKDF2) | Yes |
| nlohmann-json | JSON parsing for configuration | Yes |
| ClamAV | Virus scanning with clamscan | Optional |
| espeak | Text-to-speech for Guardi (Linux only) | Optional |

### Network Requirements

| Service | URL | Purpose |
|---------|-----|---------|
| HaveIBeenPwned | api.pwnedpasswords.com | Password breach checking |
| WHOIS servers | Various | Domain registration lookup |
| IMAP servers | Provider-specific | Email protection |

**Note:** All network features require an active internet connection. The application will still function offline but network-dependent features will be unavailable.

---

## Setup

### Automated Setup (Recommended)

Run the setup script to automatically install dependencies and compile:

```bash
cd guardme_cpp
chmod +x setup.sh
./setup.sh
```

The script will:
1. Display a menu to choose Console, GUI, or Both versions
2. Detect your package manager (apt, dnf, pacman, brew, nix)
3. Install any missing dependencies
4. Check for/create the build directory
5. Compile the selected version(s)
6. Ask if you want to run the application

### Manual Setup

#### Console Version

Install dependencies:
```bash
# Ubuntu/Debian
sudo apt install g++ pkg-config libcurl4-openssl-dev libssl-dev clamav

# macOS
brew install curl openssl clamav

# Fedora
sudo dnf install gcc-c++ libcurl-devel openssl-devel clamav
```

Compile:
```bash
cd guardme_cpp
mkdir -p build
g++ -std=c++17 -Wall -O2 \
    $(pkg-config --cflags libcurl openssl) \
    -o build/guardme_console src/console_main.cpp \
    $(pkg-config --libs libcurl openssl)
```

Run:
```bash
./build/guardme_console
```

#### GUI Version

Install dependencies:
```bash
# Ubuntu/Debian
sudo apt install cmake qt6-base-dev qt6-tools-dev libgl1-mesa-dev \
    libcurl4-openssl-dev libssl-dev nlohmann-json3-dev clamav

# macOS
brew install cmake qt@6 curl openssl nlohmann-json clamav
```

Compile:
```bash
cd guardme_cpp
mkdir -p build && cd build
cmake ..
make -j$(nproc)
```

Run:
```bash
./build/GuardME
```

### Troubleshooting

#### macOS CMake Parse Error

If you see this error when building the GUI version:
```
CMake Error: Parse error. Expected "(", got unquoted argument with text ":=".
```

This is a CMake version mismatch. Fix it by updating CMake:
```bash
brew upgrade cmake
```

Then clean the build directory and rebuild:
```bash
rm -rf build
mkdir build && cd build
cmake ..
make -j$(sysctl -n hw.ncpu)
```

#### Qt6 Not Found on macOS

If CMake can't find Qt6, specify the path manually:
```bash
cmake -DCMAKE_PREFIX_PATH="/opt/homebrew/opt/qt" ..
```

For Intel Macs, use:
```bash
cmake -DCMAKE_PREFIX_PATH="/usr/local/opt/qt" ..
```

---

## Features

### URL Threat Analysis

Analyzes any URL for potential security threats using heuristic scoring.

**What it checks:**
- HTTPS vs HTTP (secure connection)
- IP address-based URLs (often used by attackers)
- Suspicious top-level domains (.xyz, .tk, .top, etc.)
- Excessive subdomains (sign of phishing)
- URL length (very long URLs are suspicious)
- Phishing keywords (login, verify, account, secure, etc.)
- Known URL shorteners that hide destinations

**How to use (Console):**
1. Select option 1 "Analyze URL for threats" from the menu
2. Enter the URL you want to check
3. View the threat score (0-100) and risk level

**How to use (GUI):**
1. Go to the Tools tab
2. Enter the URL in the "URL Analysis" section
3. Click "Analyze" to see the threat score and risk breakdown

**Risk levels:**
- 0-20: Safe
- 21-40: Low Risk
- 41-60: Medium Risk
- 61-80: High Risk
- 81-100: Critical

---

### Password Breach Checker

Checks if your password has appeared in known data breaches using the HaveIBeenPwned database.

**How it works (k-anonymity):**
1. Your password is hashed locally using SHA-1
2. Only the first 5 characters of the hash are sent to the API
3. The API returns all breached hashes starting with those characters
4. Your full hash is checked locally against the results
5. Your actual password NEVER leaves your computer

**How to use (Console):**
1. Select option 2 "Check password breach status" from the menu
2. Enter the password you want to check
3. See if it has been found in any breaches and how many times

**How to use (GUI):**
1. Go to the Tools tab
2. Enter your password in the "Password Breach Check" section
3. Click "Check" to see breach results

**Note:** This feature is completely free and requires no API key.

---

### Password Generator

Generates secure random 8-character passwords that you can copy to your clipboard.

**Password composition:**
- Uppercase letters (A-Z)
- Lowercase letters (a-z)
- Numbers (0-9)
- Special characters (!@#$%^&*)

**Console usage:**
1. Select option **9** from the main menu
2. A random password will be displayed in green
3. Copy it using your terminal's copy shortcut (Ctrl+Shift+C or similar)

**GUI usage:**
1. Go to the **Tools** tab
2. Find the **Password Generator** section
3. Click **Generate** to create a new password
4. Click **Copy to Clipboard** to copy it

**Tip:** Generate a new password each time you need one for a new account. Never reuse passwords across sites!

---

### Virus Scanner

Scans files and folders for viruses and malware using the ClamAV antivirus engine with **automatic threat quarantine**.

**What it does:**
- Scans individual files or entire directories
- Recursively checks all files in folders
- Identifies specific malware names when threats are found
- **Automatically quarantines detected threats** (see below)
- Reports clean files as safe

**Automatic Quarantine:**

When a threat is detected, GuardME takes immediate protective action:

1. **Strips executable permissions** - Removes execute permissions from the infected file so it cannot be run
2. **Moves to quarantine** - Relocates the file to a secure quarantine directory
3. **Renames with timestamp** - Files are renamed with format: `timestamp_filename.quarantine`

| Setting | Value |
|---------|-------|
| Quarantine location | `/tmp/guardme_quarantine/` |
| Directory permissions | 700 (owner only) |
| File naming | `1735441234_malware.exe.quarantine` |

**Example output:**
```
--- Scan Results ---
Files Scanned: 5
Threats Found: 1

Threats Detected:
  /path/to/malware.exe: Win.Trojan.Agent FOUND

Quarantined Files:
  -> /tmp/guardme_quarantine/1735441234_malware.exe.quarantine

Action Taken:
  - Executable permissions removed
  - Files moved to quarantine: /tmp/guardme_quarantine
```

**Weekly Update Reminders:**

GuardME tracks when ClamAV definitions were last updated and reminds you weekly to run `freshclam`. This ensures your virus definitions stay current for maximum protection.

**How to use (Console):**
1. Select option 3 "Scan file/folder for viruses" from the menu
2. Enter the path to a file or folder
3. View scan results showing detected threats and quarantine actions

**How to use (GUI):**
1. Go to the Tools tab
2. Click "Browse Files" to select a specific file, or "Browse Folders" to select an entire directory
3. Click "Start Scan" to run the antivirus check
4. Results show detected threats and any quarantine actions taken

**Requirements:**
- ClamAV must be installed (`clamscan` command available)
- Run `sudo freshclam` weekly to update virus definitions (GuardME will remind you)

---

### System Health Monitor

Monitors your computer's resource usage to help identify suspicious activity.

**What it shows:**
- CPU usage percentage
- Memory usage (used/total in MB)
- Memory usage percentage

**Why it matters:**
- Unusually high CPU usage could indicate crypto-mining malware
- Memory spikes might reveal malicious processes
- Regular monitoring helps establish a baseline for normal activity

**How to use (Console):**
1. Select option 4 "View system health" from the menu
2. View current CPU and memory statistics

**How to use (GUI):**
1. Go to the Dashboard tab
2. System health metrics are displayed automatically
3. CPU and memory usage update in real-time

---

### File Threat Assessment

Analyzes individual files for suspicious characteristics without requiring virus signatures.

**What it checks:**
- **File entropy**: Measures randomness in file content. Very high entropy (above 7.5/8.0) can indicate encrypted or packed malware
- **File extension**: Flags dangerous extensions like .exe, .dll, .bat, .cmd, .ps1, .vbs, .js, .scr
- **Overall threat level**: Combines factors into Low/Medium/High assessment

**How to use (Console):**
1. Select option 5 "Assess file threat level" from the menu
2. Enter the path to the file
3. View entropy score and threat assessment

**How to use (GUI):**
1. Go to the Tools tab
2. Enter a file path in the "File Assessment" section
3. Click "Assess" to analyze the file's threat level

---

### Meet Guardi - Your Security Assistant

Say hello to **Guardi**, GuardME's friendly cybersecurity companion! Guardi is always ready to help you navigate the digital world safely. Whether you're confused about a security warning, wondering if an email looks suspicious, or just want to learn how to stay safer online, Guardi has your back.

**Who is Guardi?**
Guardi is a cross between a scarab and a beetle - a sturdy little guardian bug who takes protecting you seriously! As your personal security sidekick, Guardi is approachable, knowledgeable, and never judgmental. No question is too simple! Guardi believes everyone deserves to feel confident about their online safety, and explains complex security topics in plain, friendly language.

**What Guardi can help with:**
- 🛡️ Explaining GuardME features and how to use them
- 🔐 Password security tips and best practices
- 🎣 Spotting phishing emails and scam websites
- 🌐 Safe browsing habits and privacy protection
- 🦠 Understanding malware and how to avoid it
- 💡 General cybersecurity advice for everyday life

**How to chat with Guardi (Console):**
1. Select option 7 "Interactive chatbot help" from the menu
2. Type your question or topic - Guardi is listening!
3. Type "exit" when you're done to return to the main menu

**How to chat with Guardi (GUI):**
1. Click the chat icon (💬) in the bottom-right corner of any tab
2. Type your security question in the chat box
3. Guardi will respond with helpful, friendly advice

**Text-to-Speech (GUI):**
Guardi can read responses out loud! Enable the "Speak responses" checkbox in the chat window header to hear Guardi's advice.

| Platform | Speech Engine |
|----------|---------------|
| Linux | espeak |
| macOS | say (built-in) |

The setup script automatically installs espeak on Linux systems. On macOS, no additional software is needed.

---

### Download Monitor

Watches your downloads folder in real-time and automatically scans new files for malware using ClamAV. If a threat is detected, the file is immediately quarantined before you can accidentally open it.

**How it works:**
1. Monitors a specified folder (defaults to `~/Downloads`)
2. Detects new files as they appear
3. Waits for download to complete (ignores `.part`, `.crdownload`, `.tmp` files)
4. Scans completed files with ClamAV
5. Quarantines any detected malware automatically

**Features:**
| Feature | Description |
|---------|-------------|
| Real-time monitoring | Checks every 2 seconds for new files |
| Auto-quarantine | Malware moved to `/tmp/guardme_quarantine/` |
| Background operation | Runs in background while you use other features |
| Statistics tracking | Shows files scanned and threats blocked |

**How to use (Console):**
1. Select "Download Monitor" from the menu
2. Choose "Start monitoring"
3. Enter the folder path (or press Enter for default `~/Downloads`)
4. The monitor runs in the background
5. You'll see alerts if malware is detected

**How to use (GUI):**
1. Go to the Controls tab
2. Enable "Download Protection"
3. Click "Browse Folders" to select your downloads folder
4. Monitor runs automatically in the background

**Requirements:**
- ClamAV must be installed (`clamscan` command available)

---

### WHOIS Lookup (GUI)

*Available in GUI version only*

Retrieves domain registration information to verify website legitimacy.

**What it shows:**
- Domain registrar
- Registration date
- Expiration date
- Registrant information (if public)

---

### Email Protection (GUI)

*Available in GUI version only*

Connects to your email via IMAP to scan for phishing attempts, suspicious links, and security threats.

**Wizard-Guided Setup:**
The email protection feature includes a step-by-step setup wizard:
1. **Step 1**: Choose your email provider (Gmail, Outlook, Yahoo, iCloud, or custom IMAP)
2. **Step 2**: Enter your email address and app password, then test or connect
3. **Step 3**: Automatic connection and email fetching

**Test Connection Feature:**
Before saving your credentials, you can test if they work:
- Click "🔌 Test Connection" to verify your credentials without saving them
- If the test succeeds, you'll be prompted to connect and save
- If the test fails, you can adjust your credentials and try again
- Use "Connect & Save →" to connect and save credentials in one step

**Supported Providers:**
| Provider | IMAP Server | Port |
|----------|-------------|------|
| Gmail | imap.gmail.com | 993 |
| Outlook/Hotmail | imap-mail.outlook.com | 993 |
| Yahoo Mail | imap.mail.yahoo.com | 993 |
| iCloud | imap.mail.me.com | 993 |
| Custom | User-defined | User-defined |

**Security Analysis:**
Each email is analyzed for:
- **Sender Verification**: Checks if display name matches email address
- **Suspicious Links**: Detects links to known malicious TLDs or IP-based URLs
- **Phishing Indicators**: Scans for urgent/threatening language patterns
- **Attachment Warnings**: Alerts when emails contain attachments

**Spam Scoring:**
- 🟢 **0-24%**: Low Risk - Email appears safe
- 🟡 **25-49%**: Medium Risk - Some suspicious elements detected
- 🔴 **50%+**: High Risk - Multiple warning signs detected

**App Password Requirement:**
For Gmail, Outlook, and Yahoo, you need to use an App Password (not your regular password):
- Gmail: Settings → Security → 2-Step Verification → App passwords
- Outlook: Security settings → Advanced security → App passwords
- Yahoo: Account Info → Account Security → Generate app password

### Secure Credential Storage (GUI)

*Available in GUI version only*

GuardME includes encrypted credential storage so you don't have to re-enter your email password each time.

| Feature | Description |
|---------|-------------|
| Encryption | AES-256-CBC with PBKDF2 key derivation |
| Key Iterations | 100,000 (OWASP recommended) |
| Master Password | Required to unlock your saved credentials |
| Storage Location | `~/.guardme/credentials.vault` |

**How it works:**
1. **First-time setup**: When you first open Email Protection, you'll be prompted to create a master password
2. **Unlocking the vault**: On subsequent visits, enter your master password to unlock saved credentials
3. **Automatic credential saving**: After a successful email connection, your credentials are encrypted and saved (if enabled)
4. **Forget credentials**: Click "Forget Saved Credentials" anytime to permanently delete stored login info

**Forgot Master Password:**
If you forget your master password, you can reset it by verifying your email credentials:
1. Click "Forgot Master Password?" on the vault page
2. Enter your email address and email password (the same credentials you originally saved)
3. Select your email provider
4. GuardME will connect to your email server to verify you own the account
5. If verification succeeds, you'll be prompted to create a new master password
6. Your credentials are re-saved with the new master password

**Security notes:**
- Your master password is never stored - only a verification hash is saved
- Credentials are only saved after a successful connection (invalid passwords aren't stored)
- Custom IMAP server and port settings are preserved
- If the vault is locked when you try to save, you'll receive a warning
- Password reset requires proving ownership via successful email connection

---

## Project Structure

```
guardme_cpp/
├── setup.sh                # Automated setup script
├── instructions.txt        # Detailed installation guide
├── CMakeLists.txt          # GUI build configuration
├── Makefile                # Console build configuration
├── src/
│   ├── console_main.cpp    # Console application
│   ├── main.cpp            # GUI entry point
│   ├── gui/                # GUI components
│   │   ├── mainwindow.cpp
│   │   ├── dashboardtab.cpp
│   │   ├── controlstab.cpp
│   │   ├── toolstab.cpp
│   │   ├── emailprotectiontab.cpp
│   │   ├── alertstab.cpp
│   │   ├── apistatustab.cpp
│   │   └── chatbotwidget.cpp
│   ├── core/               # Core utilities
│   │   ├── configmanager.cpp
│   │   └── logger.cpp
│   ├── security/           # Security modules
│   │   ├── urlanalyzer.cpp
│   │   ├── virusscanner.cpp
│   │   ├── credentialvault.cpp
│   │   ├── whoisanalyzer.cpp
│   │   └── sslanalyzer.cpp
│   ├── network/            # Network modules
│   │   ├── httpclient.cpp
│   │   └── breachcheck.cpp
│   └── utils/              # Utilities
│       └── systemmonitor.cpp
├── include/                # Header files
├── resources/              # Images and data files
│   ├── images/
│   │   ├── guardi_cartoon.png
│   │   ├── guardi_happy.png
│   │   └── guardi_distressed.png
│   ├── guardi_responses.json
│   └── resources.qrc
└── build/                  # Compiled binaries
    ├── guardme_console     # Console executable
    └── GuardME             # GUI executable
```

---

## Contributing

Contributions are welcome and appreciated! Whether you're fixing bugs, adding new features, improving documentation, or suggesting ideas, your help makes GuardME better for everyone.

**Ways to contribute:**
- Report bugs or security vulnerabilities
- Suggest new features or improvements
- Submit pull requests with fixes or enhancements
- Improve documentation or add examples
- Share feedback on your experience using GuardME

**Getting started:**
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes and test thoroughly
4. Commit with clear, descriptive messages
5. Submit a pull request

Thank you to everyone who contributes to making GuardME a stronger security tool!

---

## License

MIT License - See LICENSE file for details.
