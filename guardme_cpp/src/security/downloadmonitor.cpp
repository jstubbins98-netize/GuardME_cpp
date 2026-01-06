#include "security/downloadmonitor.h"
#include "security/virusscanner.h"
#include "core/configmanager.h"
#include "core/logger.h"
#include <QDir>
#include <QFileInfo>
#include <QTimer>

DownloadMonitor::DownloadMonitor() : monitoring(false) {
    watcher = new QFileSystemWatcher(this);
    connect(watcher, &QFileSystemWatcher::directoryChanged, 
            this, &DownloadMonitor::onDirectoryChanged);
}

DownloadMonitor::~DownloadMonitor() {
    stopMonitoring();
}

void DownloadMonitor::startMonitoring(const QString& path) {
    if (monitoring) {
        stopMonitoring();
    }
    
    monitoredPath = path;
    
    QDir dir(path);
    if (!dir.exists()) {
        Logger::getInstance().log(Logger::ERROR_LEVEL, 
            QString("Download monitor path does not exist: %1").arg(path));
        return;
    }
    
    QFileInfoList files = dir.entryInfoList(QDir::Files);
    for (const QFileInfo& fileInfo : files) {
        knownFiles.insert(fileInfo.absoluteFilePath());
    }
    
    watcher->addPath(path);
    monitoring = true;
    
    Logger::getInstance().log(Logger::SUCCESS, 
        QString("Download monitor started for: %1").arg(path));
}

void DownloadMonitor::stopMonitoring() {
    if (!monitoring) return;
    
    watcher->removePath(monitoredPath);
    knownFiles.clear();
    monitoring = false;
    
    Logger::getInstance().log(Logger::INFO, "Download monitor stopped");
}

bool DownloadMonitor::isExcludedExtension(const QString& filePath) {
    QFileInfo fileInfo(filePath);
    QString suffix = "." + fileInfo.suffix().toLower();
    
    QStringList excluded = ConfigManager::getInstance().getExcludedExtensions();
    return excluded.contains(suffix);
}

void DownloadMonitor::onDirectoryChanged(const QString& path) {
    QDir dir(path);
    QFileInfoList files = dir.entryInfoList(QDir::Files);
    
    for (const QFileInfo& fileInfo : files) {
        QString filePath = fileInfo.absoluteFilePath();
        
        if (!knownFiles.contains(filePath)) {
            knownFiles.insert(filePath);
            
            QTimer::singleShot(1000, this, [this, filePath]() {
                processNewFile(filePath);
            });
        }
    }
    
    QSet<QString> currentFiles;
    for (const QFileInfo& fileInfo : files) {
        currentFiles.insert(fileInfo.absoluteFilePath());
    }
    knownFiles = knownFiles.intersect(currentFiles);
}

void DownloadMonitor::processNewFile(const QString& filePath) {
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists()) return;
    
    Logger::getInstance().log(Logger::INFO, 
        QString("New download detected: %1").arg(fileInfo.fileName()));
    
    emit newFileDetected(filePath);
    
    if (isExcludedExtension(filePath)) {
        Logger::getInstance().log(Logger::INFO, 
            QString("File excluded by extension: %1").arg(filePath));
        emit fileSafe(filePath);
        return;
    }
    
    if (ConfigManager::getInstance().isVirusScanEnabled()) {
        VirusScanner::ScanResult result = VirusScanner::getInstance().scanPath(filePath, true);
        
        if (!result.success) {
            Logger::getInstance().log(Logger::WARNING, 
                QString("Scan failed for: %1 - %2").arg(filePath, result.errorMessage));
            return;
        }
        
        if (result.threatsFound > 0) {
            QString threatInfo = result.threats.join(", ");
            Logger::getInstance().log(Logger::WARNING, 
                QString("MALWARE BLOCKED: %1 - %2").arg(filePath, threatInfo));
            
            knownFiles.remove(filePath);
            emit threatDetected(filePath, threatInfo);
        } else {
            Logger::getInstance().log(Logger::SUCCESS, 
                QString("Download safe: %1").arg(filePath));
            emit fileSafe(filePath);
        }
    } else {
        emit fileSafe(filePath);
    }
}
