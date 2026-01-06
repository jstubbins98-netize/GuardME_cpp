#ifndef CONFIGMANAGER_H
#define CONFIGMANAGER_H

#include <QString>
#include <QStringList>
#include <QSettings>
#include <nlohmann/json.hpp>
#include <fstream>

class ConfigManager {
public:
    static ConfigManager& getInstance() {
        static ConfigManager instance;
        return instance;
    }
    
    void loadConfig();
    void saveConfig();
    
    bool isUrlMonitorEnabled() const { return urlMonitorEnabled; }
    void setUrlMonitorEnabled(bool enabled) { urlMonitorEnabled = enabled; saveConfig(); }
    
    bool isDownloadMonitorEnabled() const { return downloadMonitorEnabled; }
    void setDownloadMonitorEnabled(bool enabled) { downloadMonitorEnabled = enabled; saveConfig(); }
    
    bool isVirusScanEnabled() const { return virusScanEnabled; }
    void setVirusScanEnabled(bool enabled) { virusScanEnabled = enabled; saveConfig(); }
    
    QStringList getWhitelistedDomains() const { return whitelistedDomains; }
    void addWhitelistedDomain(const QString& domain);
    void removeWhitelistedDomain(const QString& domain);
    
    QStringList getExcludedExtensions() const { return excludedExtensions; }
    void setExcludedExtensions(const QStringList& extensions) { excludedExtensions = extensions; saveConfig(); }
    
    QString getDownloadsPath() const { return downloadsPath; }
    void setDownloadsPath(const QString& path) { downloadsPath = path; saveConfig(); }
    
private:
    ConfigManager();
    ~ConfigManager() = default;
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;
    
    QString configFilePath;
    bool urlMonitorEnabled;
    bool downloadMonitorEnabled;
    bool virusScanEnabled;
    QStringList whitelistedDomains;
    QStringList excludedExtensions;
    QString downloadsPath;
};

#endif
