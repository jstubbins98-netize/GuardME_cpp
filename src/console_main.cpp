#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <regex>
#include <chrono>
#include <thread>
#include <map>
#include <set>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <atomic>
#include <mutex>
#include <dirent.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <ctime>

const std::string CLAMAV_REMINDER_FILE = "/tmp/.guardme_clamav_reminder";
const int REMINDER_INTERVAL_DAYS = 7;

bool shouldShowClamAVReminder() {
    struct stat fileStat;
    if (stat(CLAMAV_REMINDER_FILE.c_str(), &fileStat) != 0) {
        return true;
    }
    
    auto now = std::chrono::system_clock::now();
    auto fileTime = std::chrono::system_clock::from_time_t(fileStat.st_mtime);
    auto daysSinceReminder = std::chrono::duration_cast<std::chrono::hours>(now - fileTime).count() / 24;
    
    return daysSinceReminder >= REMINDER_INTERVAL_DAYS;
}

void updateReminderTimestamp() {
    std::ofstream file(CLAMAV_REMINDER_FILE);
    file << std::chrono::system_clock::now().time_since_epoch().count();
    file.close();
}

void showClamAVReminder() {
    if (shouldShowClamAVReminder()) {
        std::cout << "\n\033[33m";
        std::cout << "============================================================\n";
        std::cout << "  WEEKLY REMINDER: Update your ClamAV virus definitions!\n";
        std::cout << "  Run:  sudo freshclam\n";
        std::cout << "============================================================\n";
        std::cout << "\033[0m\n";
        updateReminderTimestamp();
    }
}

class Logger {
public:
    enum Level { DEBUG, INFO, WARNING, ERROR_LEVEL, SUCCESS };
    
    static void log(Level level, const std::string& message) {
        std::string levelStr;
        std::string color;
        
        switch (level) {
            case DEBUG: levelStr = "DEBUG"; color = "\033[36m"; break;
            case INFO: levelStr = "INFO"; color = "\033[34m"; break;
            case WARNING: levelStr = "WARNING"; color = "\033[33m"; break;
            case ERROR_LEVEL: levelStr = "ERROR"; color = "\033[31m"; break;
            case SUCCESS: levelStr = "SUCCESS"; color = "\033[32m"; break;
        }
        
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        char timeStr[20];
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", localtime(&time));
        
        std::cout << color << "[" << timeStr << "] [" << levelStr << "] " 
                  << message << "\033[0m" << std::endl;
    }
};

class UrlAnalyzer {
public:
    struct AnalysisResult {
        int score;
        std::string threatLevel;
        std::vector<std::string> details;
    };
    
    static AnalysisResult analyze(const std::string& url) {
        AnalysisResult result;
        result.score = 0;
        
        std::string lower = url;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        
        if (url.substr(0, 5) != "https") {
            result.score += 15;
            result.details.push_back("Not using HTTPS");
        }
        
        std::regex ipRegex(R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})");
        if (std::regex_search(url, ipRegex)) {
            result.score += 25;
            result.details.push_back("Uses IP address instead of domain");
        }
        
        if (url.length() > 75) {
            result.score += 10;
            result.details.push_back("Unusually long URL");
        }
        
        std::vector<std::string> suspiciousTlds = {".xyz", ".top", ".club", ".tk", ".ml"};
        for (const auto& tld : suspiciousTlds) {
            if (lower.find(tld) != std::string::npos) {
                result.score += 20;
                result.details.push_back("Suspicious TLD: " + tld);
                break;
            }
        }
        
        std::vector<std::string> suspiciousKeywords = {"login", "signin", "verify", "secure", "account"};
        for (const auto& keyword : suspiciousKeywords) {
            if (lower.find(keyword) != std::string::npos) {
                result.score += 10;
                result.details.push_back("Contains suspicious keyword: " + keyword);
                break;
            }
        }
        
        if (result.score >= 60) result.threatLevel = "CRITICAL";
        else if (result.score >= 40) result.threatLevel = "HIGH";
        else if (result.score >= 25) result.threatLevel = "MEDIUM";
        else if (result.score >= 10) result.threatLevel = "LOW";
        else result.threatLevel = "SAFE";
        
        return result;
    }
};

class VirusScanner {
public:
    struct ScanResult {
        bool available;
        bool success;
        std::string errorMessage;
        int filesScanned;
        int threatsFound;
        std::vector<std::string> threats;
        std::vector<std::string> quarantinedFiles;
    };
    
    static const std::string QUARANTINE_DIR;
    
    static bool isAvailable() {
        return system("which clamscan > /dev/null 2>&1") == 0;
    }
    
    static bool ensureQuarantineDir() {
        struct stat st;
        if (stat(QUARANTINE_DIR.c_str(), &st) != 0) {
            if (mkdir(QUARANTINE_DIR.c_str(), 0700) != 0) {
                Logger::log(Logger::ERROR_LEVEL, "Failed to create quarantine directory");
                return false;
            }
            Logger::log(Logger::INFO, "Created quarantine directory: " + QUARANTINE_DIR);
        }
        return true;
    }
    
    static bool stripExecutablePermissions(const std::string& filePath) {
        struct stat st;
        if (stat(filePath.c_str(), &st) != 0) {
            return false;
        }
        
        mode_t newMode = st.st_mode & ~(S_IXUSR | S_IXGRP | S_IXOTH);
        if (chmod(filePath.c_str(), newMode) == 0) {
            Logger::log(Logger::SUCCESS, "Stripped executable permissions from: " + filePath);
            return true;
        }
        return false;
    }
    
    static std::string quarantineFile(const std::string& filePath) {
        if (!ensureQuarantineDir()) {
            return "";
        }
        
        size_t lastSlash = filePath.find_last_of('/');
        std::string filename = (lastSlash != std::string::npos) ? filePath.substr(lastSlash + 1) : filePath;
        
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        
        std::string quarantinePath = QUARANTINE_DIR + "/" + std::to_string(timestamp) + "_" + filename + ".quarantine";
        
        stripExecutablePermissions(filePath);
        
        if (rename(filePath.c_str(), quarantinePath.c_str()) == 0) {
            Logger::log(Logger::SUCCESS, "Quarantined file: " + filePath + " -> " + quarantinePath);
            return quarantinePath;
        } else {
            Logger::log(Logger::ERROR_LEVEL, "Failed to quarantine file: " + filePath);
            return "";
        }
    }
    
    static ScanResult scan(const std::string& path, bool autoQuarantine = true) {
        ScanResult result;
        result.filesScanned = 0;
        result.threatsFound = 0;
        result.available = isAvailable();
        result.success = false;
        
        if (!result.available) {
            result.errorMessage = "ClamAV not available";
            Logger::log(Logger::WARNING, "ClamAV not available. Install with: sudo apt install clamav");
            return result;
        }
        
        std::string command = "clamscan --infected --recursive \"" + path + "\" 2>&1; echo EXIT_CODE:$?";
        FILE* pipe = popen(command.c_str(), "r");
        if (!pipe) {
            result.errorMessage = "Failed to execute clamscan";
            return result;
        }
        
        char buffer[256];
        std::string output;
        std::vector<std::string> infectedFiles;
        int exitCode = -1;
        
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            std::string line(buffer);
            if (line.find("EXIT_CODE:") == 0) {
                try {
                    exitCode = std::stoi(line.substr(10));
                } catch (...) {}
                continue;
            }
            output += buffer;
            if (strstr(buffer, "FOUND")) {
                result.threats.push_back(buffer);
                result.threatsFound++;
                
                size_t colonPos = line.find(':');
                if (colonPos != std::string::npos) {
                    std::string infectedPath = line.substr(0, colonPos);
                    infectedFiles.push_back(infectedPath);
                }
            }
        }
        pclose(pipe);
        
        if (exitCode == 0 || exitCode == 1) {
            result.success = true;
        } else {
            result.errorMessage = "ClamAV scan failed (exit code: " + std::to_string(exitCode) + ")";
            return result;
        }
        
        std::regex scannedRegex(R"(Scanned files:\s*(\d+))");
        std::smatch match;
        if (std::regex_search(output, match, scannedRegex)) {
            result.filesScanned = std::stoi(match[1]);
        }
        
        if (autoQuarantine && !infectedFiles.empty()) {
            Logger::log(Logger::WARNING, "Found " + std::to_string(infectedFiles.size()) + " infected file(s). Quarantining...");
            for (const auto& infectedFile : infectedFiles) {
                std::string quarantinedPath = quarantineFile(infectedFile);
                if (!quarantinedPath.empty()) {
                    result.quarantinedFiles.push_back(quarantinedPath);
                }
            }
        }
        
        return result;
    }
};

const std::string VirusScanner::QUARANTINE_DIR = "/tmp/guardme_quarantine";

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t totalSize = size * nmemb;
    output->append((char*)contents, totalSize);
    return totalSize;
}

class BreachCheck {
public:
    static std::string sha1Hash(const std::string& input) {
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1((unsigned char*)input.c_str(), input.length(), hash);
        
        char hexStr[SHA_DIGEST_LENGTH * 2 + 1];
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
            sprintf(hexStr + (i * 2), "%02X", hash[i]);
        }
        return std::string(hexStr);
    }
    
    static std::pair<bool, int> checkPassword(const std::string& password) {
        std::string hash = sha1Hash(password);
        std::string prefix = hash.substr(0, 5);
        std::string suffix = hash.substr(5);
        
        CURL* curl = curl_easy_init();
        if (!curl) return {false, 0};
        
        std::string url = "https://api.pwnedpasswords.com/range/" + prefix;
        std::string response;
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "GuardME/1.0");
        
        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        if (res != CURLE_OK) {
            Logger::log(Logger::ERROR_LEVEL, "Failed to check password breach");
            return {false, 0};
        }
        
        std::istringstream stream(response);
        std::string line;
        while (std::getline(stream, line)) {
            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos) {
                std::string hashSuffix = line.substr(0, colonPos);
                while (!hashSuffix.empty() && (hashSuffix.back() == '\r' || hashSuffix.back() == '\n')) {
                    hashSuffix.pop_back();
                }
                if (hashSuffix == suffix) {
                    int count = std::stoi(line.substr(colonPos + 1));
                    return {true, count};
                }
            }
        }
        
        return {false, 0};
    }
};

class SystemMonitor {
public:
    static int getCpuUsage() {
        std::ifstream file("/proc/stat");
        if (!file.is_open()) return 0;
        
        std::string line;
        std::getline(file, line);
        file.close();
        
        if (line.substr(0, 3) != "cpu") return 0;
        
        std::istringstream iss(line.substr(4));
        long user, nice, system, idle, iowait;
        iss >> user >> nice >> system >> idle >> iowait;
        
        long total = user + nice + system + idle + iowait;
        long active = user + nice + system;
        
        return (total > 0) ? (100 * active / total) : 0;
    }
    
    static int getMemoryUsage() {
        std::ifstream file("/proc/meminfo");
        if (!file.is_open()) return 0;
        
        long total = 0, available = 0;
        std::string line;
        
        while (std::getline(file, line)) {
            if (line.find("MemTotal:") == 0) {
                std::istringstream iss(line.substr(10));
                iss >> total;
            } else if (line.find("MemAvailable:") == 0) {
                std::istringstream iss(line.substr(14));
                iss >> available;
            }
        }
        file.close();
        
        return (total > 0) ? (100 * (total - available) / total) : 0;
    }
};

class ThreatDetector {
public:
    static double calculateEntropy(const std::vector<unsigned char>& data) {
        if (data.empty()) return 0.0;
        
        int freq[256] = {0};
        for (unsigned char byte : data) {
            freq[byte]++;
        }
        
        double entropy = 0.0;
        for (int i = 0; i < 256; i++) {
            if (freq[i] > 0) {
                double p = (double)freq[i] / data.size();
                entropy -= p * log2(p);
            }
        }
        return entropy;
    }
    
    static std::string assessFile(const std::string& filePath) {
        double score = 0.0;
        std::vector<std::string> indicators;
        
        std::vector<std::string> dangerousExts = {".exe", ".bat", ".cmd", ".scr", ".vbs", ".js"};
        for (const auto& ext : dangerousExts) {
            if (filePath.length() >= ext.length() &&
                filePath.substr(filePath.length() - ext.length()) == ext) {
                score += 0.3;
                indicators.push_back("Dangerous extension");
                break;
            }
        }
        
        std::ifstream file(filePath, std::ios::binary);
        if (file.is_open()) {
            std::vector<unsigned char> buffer(8192);
            file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
            buffer.resize(file.gcount());
            file.close();
            
            double entropy = calculateEntropy(buffer);
            if (entropy > 7.5) {
                score += 0.2;
                indicators.push_back("High entropy (possible encryption/packing)");
            }
        }
        
        if (score >= 0.6) return "HIGH RISK";
        if (score >= 0.3) return "MEDIUM RISK";
        return "LOW RISK";
    }
};

class DownloadMonitor {
public:
    static std::atomic<bool> running;
    static std::atomic<int> filesScanned;
    static std::atomic<int> threatsBlocked;
    static std::string watchPath;
    static std::set<std::string> knownFiles;
    static std::mutex filesMutex;
    
    static std::set<std::string> getDirectoryFiles(const std::string& path) {
        std::set<std::string> files;
        DIR* dir = opendir(path.c_str());
        if (!dir) return files;
        
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_type == DT_REG) {
                std::string filename(entry->d_name);
                if (filename.find(".part") == std::string::npos &&
                    filename.find(".crdownload") == std::string::npos &&
                    filename.find(".tmp") == std::string::npos) {
                    files.insert(path + "/" + filename);
                }
            }
        }
        closedir(dir);
        return files;
    }
    
    static void monitorLoop() {
        Logger::log(Logger::SUCCESS, "Download monitor started for: " + watchPath);
        
        {
            std::lock_guard<std::mutex> lock(filesMutex);
            knownFiles = getDirectoryFiles(watchPath);
        }
        
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            
            auto currentFiles = getDirectoryFiles(watchPath);
            
            std::vector<std::string> newFiles;
            {
                std::lock_guard<std::mutex> lock(filesMutex);
                for (const auto& file : currentFiles) {
                    if (knownFiles.find(file) == knownFiles.end()) {
                        newFiles.push_back(file);
                        knownFiles.insert(file);
                    }
                }
            }
            
            for (const auto& file : newFiles) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                
                struct stat st;
                if (stat(file.c_str(), &st) != 0) continue;
                
                Logger::log(Logger::INFO, "New download detected: " + file);
                
                auto result = VirusScanner::scan(file);
                
                if (!result.available) {
                    Logger::log(Logger::WARNING, "ClamAV not available - file not scanned: " + file.substr(file.find_last_of('/') + 1));
                    continue;
                }
                
                if (!result.success) {
                    Logger::log(Logger::ERROR_LEVEL, "Scan failed: " + result.errorMessage + " - " + file.substr(file.find_last_of('/') + 1));
                    continue;
                }
                
                filesScanned++;
                
                if (result.threatsFound > 0) {
                    Logger::log(Logger::WARNING, "MALWARE BLOCKED: " + file);
                    std::cout << "\033[31m╔═══════════════════════════════════════════════════╗\033[0m\n";
                    std::cout << "\033[31m║         🚨 MALWARE DETECTED IN DOWNLOAD! 🚨       ║\033[0m\n";
                    std::cout << "\033[31m╠═══════════════════════════════════════════════════╣\033[0m\n";
                    std::string filename = file.substr(file.find_last_of('/') + 1);
                    size_t padLen = 44 > filename.length() ? 44 - filename.length() : 0;
                    std::cout << "\033[31m║ File: " << filename << std::string(padLen, ' ') << "║\033[0m\n";
                    std::cout << "\033[31m║ Action: File quarantined automatically            ║\033[0m\n";
                    std::cout << "\033[31m╚═══════════════════════════════════════════════════╝\033[0m\n";
                    threatsBlocked++;
                    
                    {
                        std::lock_guard<std::mutex> lock(filesMutex);
                        knownFiles.erase(file);
                    }
                } else {
                    Logger::log(Logger::SUCCESS, "Download safe: " + file.substr(file.find_last_of('/') + 1));
                }
            }
        }
        
        Logger::log(Logger::INFO, "Download monitor stopped");
    }
    
    static void start(const std::string& path) {
        if (running) {
            std::cout << "\033[33mMonitor already running. Stop it first.\033[0m\n";
            return;
        }
        
        struct stat st;
        if (stat(path.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
            std::cout << "\033[31mError: Directory does not exist: " << path << "\033[0m\n";
            return;
        }
        
        watchPath = path;
        running = true;
        filesScanned = 0;
        threatsBlocked = 0;
        
        std::thread(monitorLoop).detach();
    }
    
    static void stop() {
        if (!running) {
            std::cout << "\033[33mMonitor is not running.\033[0m\n";
            return;
        }
        running = false;
    }
    
    static void showStatus() {
        std::cout << "\n\033[36m--- Download Monitor Status ---\033[0m\n";
        std::cout << "Status: " << (running ? "\033[32mRunning\033[0m" : "\033[33mStopped\033[0m") << "\n";
        if (running) {
            std::cout << "Watching: " << watchPath << "\n";
        }
        std::cout << "Files Scanned: " << filesScanned << "\n";
        std::cout << "Threats Blocked: " << threatsBlocked << "\n";
    }
};

std::atomic<bool> DownloadMonitor::running(false);
std::atomic<int> DownloadMonitor::filesScanned(0);
std::atomic<int> DownloadMonitor::threatsBlocked(0);
std::string DownloadMonitor::watchPath;
std::set<std::string> DownloadMonitor::knownFiles;
std::mutex DownloadMonitor::filesMutex;

void printBanner() {
    std::cout << "\033[36m" << R"(
   ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ███╗   ███╗███████╗
  ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗████╗ ████║██╔════╝
  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██╔████╔██║█████╗  
  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║╚██╔╝██║██╔══╝  
  ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║ ╚═╝ ██║███████╗
   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝     ╚═╝╚══════╝
                                                                
    )" << "\033[0m";
    std::cout << "\033[33m      Advanced Cybersecurity Protection Suite v1.0 (C++)\033[0m\n\n";
}

void printMenu() {
    std::cout << "\n\033[36m═══════════════════════════════════════════════════\033[0m\n";
    std::cout << "\033[33m                    MAIN MENU\033[0m\n";
    std::cout << "\033[36m═══════════════════════════════════════════════════\033[0m\n";
    std::cout << "  1. Analyze URL for threats\n";
    std::cout << "  2. Check password breach status\n";
    std::cout << "  3. Scan file/folder for viruses\n";
    std::cout << "  4. View system health\n";
    std::cout << "  5. Assess file threat level\n";
    std::cout << "  6. Show ClamAV status\n";
    std::cout << "  7. Chat with Guardi\n";
    std::cout << "  8. Download monitor\n";
    std::cout << "  9. Generate secure password\n";
    std::cout << "  0. Exit\n";
    std::cout << "\033[36m═══════════════════════════════════════════════════\033[0m\n";
    std::cout << "Enter choice: ";
}

void chatbotInteraction() {
    std::cout << "\n\033[32m[Guardi]\033[0m Hello! I'm Guardi, your security assistant.\n";
    std::cout << "Type 'exit' to return to main menu.\n\n";
    
    std::map<std::string, std::string> responses = {
        {"url", "To check a URL for threats, select option 1 from the main menu. I'll analyze it for malware, phishing, and other security risks."},
        {"virus", "For virus scanning, select option 3. Make sure ClamAV is installed on your system."},
        {"password", "To check if your password has been compromised, select option 2. Your password is hashed before being checked."},
        {"help", "I can help with: URL scanning (1), password breach check (2), virus scanning (3), system health (4), file assessment (5)"},
        {"safe", "Stay safe online: use strong unique passwords, enable 2FA, keep software updated, be cautious of suspicious links."}
    };
    
    std::string input;
    while (true) {
        std::cout << "\033[34m[You]\033[0m ";
        std::getline(std::cin, input);
        
        if (input == "exit" || input == "quit") break;
        
        std::transform(input.begin(), input.end(), input.begin(), ::tolower);
        
        bool found = false;
        for (const auto& [key, response] : responses) {
            if (input.find(key) != std::string::npos) {
                std::cout << "\033[32m[Guardi]\033[0m " << response << "\n\n";
                found = true;
                break;
            }
        }
        
        if (!found) {
            std::cout << "\033[32m[Guardi]\033[0m I'm not sure about that. Try asking about: URL, virus, password, or type 'help'.\n\n";
        }
    }
}

int main() {
    curl_global_init(CURL_GLOBAL_ALL);
    
    printBanner();
    Logger::log(Logger::SUCCESS, "GuardME Security System initialized");
    
    showClamAVReminder();
    
    std::string input;
    int choice;
    
    while (true) {
        printMenu();
        std::getline(std::cin, input);
        
        try {
            choice = std::stoi(input);
        } catch (...) {
            choice = -1;
        }
        
        switch (choice) {
            case 1: {
                std::cout << "Enter URL to analyze: ";
                std::string url;
                std::getline(std::cin, url);
                
                auto result = UrlAnalyzer::analyze(url);
                
                std::cout << "\n\033[36m--- URL Analysis Results ---\033[0m\n";
                std::cout << "URL: " << url << "\n";
                std::cout << "Threat Score: " << result.score << "/100\n";
                
                std::string color;
                if (result.threatLevel == "CRITICAL" || result.threatLevel == "HIGH") color = "\033[31m";
                else if (result.threatLevel == "MEDIUM") color = "\033[33m";
                else color = "\033[32m";
                
                std::cout << "Threat Level: " << color << result.threatLevel << "\033[0m\n";
                
                if (!result.details.empty()) {
                    std::cout << "Findings:\n";
                    for (const auto& detail : result.details) {
                        std::cout << "  - " << detail << "\n";
                    }
                }
                break;
            }
            
            case 2: {
                std::cout << "Enter password to check: ";
                std::string password;
                std::getline(std::cin, password);
                
                Logger::log(Logger::INFO, "Checking password against breach database...");
                auto [pwned, count] = BreachCheck::checkPassword(password);
                
                if (pwned) {
                    Logger::log(Logger::WARNING, "Password found in " + std::to_string(count) + " breaches!");
                    std::cout << "\033[31mDANGER: This password has been exposed in data breaches!\033[0m\n";
                    std::cout << "Occurrences: " << count << "\n";
                    std::cout << "Recommendation: Change this password immediately!\n";
                } else {
                    Logger::log(Logger::SUCCESS, "Password not found in known breaches");
                    std::cout << "\033[32mGood news! This password was not found in known breaches.\033[0m\n";
                }
                break;
            }
            
            case 3: {
                std::cout << "Enter path to scan: ";
                std::string path;
                std::getline(std::cin, path);
                
                Logger::log(Logger::INFO, "Starting virus scan...");
                auto result = VirusScanner::scan(path);
                
                if (!result.available) {
                    std::cout << "\033[31mError: ClamAV is not installed! Please delete this binary and install ClamAV using the setup.sh file.\033[0m\n";
                } else {
                    std::cout << "\n\033[36m--- Scan Results ---\033[0m\n";
                    std::cout << "Files Scanned: " << result.filesScanned << "\n";
                    std::cout << "Threats Found: " << result.threatsFound << "\n";
                    
                    if (result.threatsFound > 0) {
                        std::cout << "\033[31mThreats Detected:\033[0m\n";
                        for (const auto& threat : result.threats) {
                            std::cout << "  " << threat;
                        }
                        
                        if (!result.quarantinedFiles.empty()) {
                            std::cout << "\n\033[33mQuarantined Files:\033[0m\n";
                            for (const auto& qFile : result.quarantinedFiles) {
                                std::cout << "  -> " << qFile << "\n";
                            }
                            std::cout << "\n\033[32mAction Taken:\033[0m\n";
                            std::cout << "  - Executable permissions removed\n";
                            std::cout << "  - Files moved to quarantine: " << VirusScanner::QUARANTINE_DIR << "\n";
                        }
                    } else {
                        std::cout << "\033[32mNo threats detected.\033[0m\n";
                    }
                }
                break;
            }
            
            case 4: {
                std::cout << "\n\033[36m--- System Health ---\033[0m\n";
                std::cout << "CPU Usage: " << SystemMonitor::getCpuUsage() << "%\n";
                std::cout << "Memory Usage: " << SystemMonitor::getMemoryUsage() << "%\n";
                break;
            }
            
            case 5: {
                std::cout << "Enter file path to assess: ";
                std::string path;
                std::getline(std::cin, path);
                
                std::string risk = ThreatDetector::assessFile(path);
                
                std::string color;
                if (risk == "HIGH RISK") color = "\033[31m";
                else if (risk == "MEDIUM RISK") color = "\033[33m";
                else color = "\033[32m";
                
                std::cout << "Threat Assessment: " << color << risk << "\033[0m\n";
                break;
            }
            
            case 6: {
                bool available = VirusScanner::isAvailable();
                if (available) {
                    Logger::log(Logger::SUCCESS, "ClamAV is installed and available");
                } else {
                    Logger::log(Logger::ERROR_LEVEL, "ClamAV is NOT installed");
                    std::cout << "\033[31mError: ClamAV is not installed! Please delete this binary and install ClamAV using the setup.sh file.\033[0m\n";
                }
                break;
            }
            
            case 7: {
                chatbotInteraction();
                break;
            }
            
            case 8: {
                std::cout << "\n\033[36m═══════════════════════════════════════════════════\033[0m\n";
                std::cout << "\033[33m              DOWNLOAD MONITOR\033[0m\n";
                std::cout << "\033[36m═══════════════════════════════════════════════════\033[0m\n";
                std::cout << "  1. Start monitoring\n";
                std::cout << "  2. Stop monitoring\n";
                std::cout << "  3. View status\n";
                std::cout << "  0. Back to main menu\n";
                std::cout << "\033[36m═══════════════════════════════════════════════════\033[0m\n";
                std::cout << "Enter choice: ";
                
                std::string subInput;
                std::getline(std::cin, subInput);
                
                int subChoice = -1;
                try { subChoice = std::stoi(subInput); } catch (...) {}
                
                switch (subChoice) {
                    case 1: {
                        if (!VirusScanner::isAvailable()) {
                            std::cout << "\033[31mError: ClamAV is required for download monitoring.\033[0m\n";
                            break;
                        }
                        
                        std::string defaultPath = std::string(getenv("HOME") ? getenv("HOME") : ".") + "/Downloads";
                        std::cout << "Enter path to monitor [" << defaultPath << "]: ";
                        std::string path;
                        std::getline(std::cin, path);
                        
                        if (path.empty()) path = defaultPath;
                        
                        DownloadMonitor::start(path);
                        std::cout << "\n\033[32mDownload monitor is now active.\033[0m\n";
                        std::cout << "New files will be scanned automatically.\n";
                        std::cout << "Malware will be quarantined immediately.\n";
                        break;
                    }
                    case 2:
                        DownloadMonitor::stop();
                        break;
                    case 3:
                        DownloadMonitor::showStatus();
                        break;
                    case 0:
                        break;
                    default:
                        std::cout << "\033[31mInvalid option.\033[0m\n";
                }
                break;
            }
            
            case 9: {
                std::cout << "\n\033[36m═══════════════════════════════════════════════════\033[0m\n";
                std::cout << "\033[33m           SECURE PASSWORD GENERATOR\033[0m\n";
                std::cout << "\033[36m═══════════════════════════════════════════════════\033[0m\n";
                
                const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
                std::string password;
                
                std::srand(static_cast<unsigned>(std::time(nullptr)));
                for (int i = 0; i < 8; ++i) {
                    password += chars[std::rand() % chars.length()];
                }
                
                std::cout << "\n  Generated Password: \033[32m" << password << "\033[0m\n\n";
                std::cout << "  To copy: Select the password above and use Ctrl+Shift+C\n";
                std::cout << "  (or your terminal's copy shortcut)\n\n";
                
                Logger::log(Logger::SUCCESS, "Password generated successfully");
                break;
            }
            
            case 0:
                Logger::log(Logger::INFO, "Exiting GuardME. Stay safe!");
                curl_global_cleanup();
                return 0;
            
            default:
                std::cout << "\033[31mInvalid option. Please try again.\033[0m\n";
        }
    }
    
    curl_global_cleanup();
    return 0;
}
