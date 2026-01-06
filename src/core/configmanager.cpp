#include "core/configmanager.h"
#include "core/logger.h"
#include <QStandardPaths>
#include <QDir>
#include <QFile>

using json = nlohmann::json;

ConfigManager::ConfigManager() 
    : urlMonitorEnabled(true),
      downloadMonitorEnabled(true),
      virusScanEnabled(true) {
    
    QString configDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(configDir);
    configFilePath = configDir + "/guardme_config.json";
    
    downloadsPath = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    
    whitelistedDomains << "google.com" << "microsoft.com" << "apple.com" 
                       << "github.com" << "stackoverflow.com";
    
    excludedExtensions << ".txt" << ".pdf" << ".doc" << ".docx" << ".jpg" << ".png";
}

void ConfigManager::loadConfig() {
    QFile file(configFilePath);
    if (!file.exists()) {
        Logger::getInstance().log(Logger::INFO, "No config file found, using defaults");
        saveConfig();
        return;
    }
    
    if (!file.open(QIODevice::ReadOnly)) {
        Logger::getInstance().log(Logger::WARNING, "Could not open config file");
        return;
    }
    
    try {
        QByteArray data = file.readAll();
        file.close();
        
        json config = json::parse(data.toStdString());
        
        if (config.contains("urlMonitorEnabled")) {
            urlMonitorEnabled = config["urlMonitorEnabled"].get<bool>();
        }
        if (config.contains("downloadMonitorEnabled")) {
            downloadMonitorEnabled = config["downloadMonitorEnabled"].get<bool>();
        }
        if (config.contains("virusScanEnabled")) {
            virusScanEnabled = config["virusScanEnabled"].get<bool>();
        }
        if (config.contains("downloadsPath")) {
            downloadsPath = QString::fromStdString(config["downloadsPath"].get<std::string>());
        }
        if (config.contains("whitelistedDomains")) {
            whitelistedDomains.clear();
            for (const auto& domain : config["whitelistedDomains"]) {
                whitelistedDomains << QString::fromStdString(domain.get<std::string>());
            }
        }
        if (config.contains("excludedExtensions")) {
            excludedExtensions.clear();
            for (const auto& ext : config["excludedExtensions"]) {
                excludedExtensions << QString::fromStdString(ext.get<std::string>());
            }
        }
        
        Logger::getInstance().log(Logger::SUCCESS, "Configuration loaded successfully");
    } catch (const std::exception& e) {
        Logger::getInstance().log(Logger::ERROR_LEVEL, QString("Failed to parse config: %1").arg(e.what()));
    }
}

void ConfigManager::saveConfig() {
    json config;
    config["urlMonitorEnabled"] = urlMonitorEnabled;
    config["downloadMonitorEnabled"] = downloadMonitorEnabled;
    config["virusScanEnabled"] = virusScanEnabled;
    config["downloadsPath"] = downloadsPath.toStdString();
    
    std::vector<std::string> domains;
    for (const QString& domain : whitelistedDomains) {
        domains.push_back(domain.toStdString());
    }
    config["whitelistedDomains"] = domains;
    
    std::vector<std::string> extensions;
    for (const QString& ext : excludedExtensions) {
        extensions.push_back(ext.toStdString());
    }
    config["excludedExtensions"] = extensions;
    
    QFile file(configFilePath);
    if (file.open(QIODevice::WriteOnly)) {
        std::string jsonStr = config.dump(4);
        file.write(jsonStr.c_str());
        file.close();
    }
}

void ConfigManager::addWhitelistedDomain(const QString& domain) {
    if (!whitelistedDomains.contains(domain)) {
        whitelistedDomains << domain;
        saveConfig();
        Logger::getInstance().log(Logger::INFO, QString("Added to whitelist: %1").arg(domain));
    }
}

void ConfigManager::removeWhitelistedDomain(const QString& domain) {
    if (whitelistedDomains.removeAll(domain) > 0) {
        saveConfig();
        Logger::getInstance().log(Logger::INFO, QString("Removed from whitelist: %1").arg(domain));
    }
}
