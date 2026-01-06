#include "security/virusscanner.h"
#include "core/logger.h"
#include <QProcess>
#include <QFileInfo>
#include <QDir>
#include <QElapsedTimer>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QDateTime>
#include <sys/stat.h>

const QString VirusScanner::QUARANTINE_DIR = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/guardme_quarantine";

VirusScanner::VirusScanner() {
    clamavAvailable = checkClamav();
}

bool VirusScanner::checkClamav() {
    QProcess process;
    
    QStringList paths = {"/usr/bin/clamscan", "/usr/local/bin/clamscan", 
                         "/opt/homebrew/bin/clamscan", "clamscan"};
    
    for (const QString& path : paths) {
        process.start(path, {"--version"});
        if (process.waitForFinished(5000)) {
            if (process.exitCode() == 0) {
                clamscanPath = path;
                QString version = QString::fromUtf8(process.readAllStandardOutput()).trimmed();
                Logger::getInstance().log(Logger::SUCCESS, 
                    QString("ClamAV found: %1").arg(version));
                return true;
            }
        }
    }
    
    Logger::getInstance().log(Logger::WARNING, "ClamAV not found on system");
    return false;
}

VirusScanner::ScanResult VirusScanner::scanFile(const QString& filePath) {
    ScanResult result;
    result.filesScanned = 0;
    result.threatsFound = 0;
    result.scanTime = 0;
    result.success = false;
    
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists()) {
        result.errorMessage = "File does not exist";
        return result;
    }
    
    if (!clamavAvailable) {
        result.errorMessage = "ClamAV is not available";
        return result;
    }
    
    QElapsedTimer timer;
    timer.start();
    
    QProcess process;
    QStringList args;
    args << "--no-summary" << filePath;
    
    process.start(clamscanPath, args);
    
    if (!process.waitForFinished(300000)) {
        result.errorMessage = "Scan timeout";
        return result;
    }
    
    result.scanTime = timer.elapsed() / 1000.0;
    
    QString output = QString::fromUtf8(process.readAllStandardOutput());
    QString errorOutput = QString::fromUtf8(process.readAllStandardError());
    
    return parseClamscanOutput(output, errorOutput, process.exitCode());
}

VirusScanner::ScanResult VirusScanner::scanPath(const QString& path, bool autoQuarantine) {
    ScanResult result;
    result.filesScanned = 0;
    result.threatsFound = 0;
    result.scanTime = 0;
    result.success = false;
    
    QFileInfo pathInfo(path);
    if (!pathInfo.exists()) {
        result.errorMessage = "Path does not exist";
        return result;
    }
    
    if (!clamavAvailable) {
        result.errorMessage = "ClamAV is not available";
        return result;
    }
    
    QElapsedTimer timer;
    timer.start();
    
    QProcess process;
    QStringList args;
    args << "-r" << "--infected" << path;
    
    process.start(clamscanPath, args);
    
    Logger::getInstance().log(Logger::INFO, QString("Starting virus scan: %1").arg(path));
    
    if (!process.waitForFinished(600000)) {
        result.errorMessage = "Scan timeout";
        return result;
    }
    
    result.scanTime = timer.elapsed() / 1000.0;
    
    QString output = QString::fromUtf8(process.readAllStandardOutput());
    QString errorOutput = QString::fromUtf8(process.readAllStandardError());
    
    return parseClamscanOutput(output, errorOutput, process.exitCode(), autoQuarantine);
}

VirusScanner::ScanResult VirusScanner::parseClamscanOutput(const QString& output, 
                                                            const QString& errorOutput, 
                                                            int exitCode,
                                                            bool autoQuarantine) {
    ScanResult result;
    result.filesScanned = 0;
    result.threatsFound = 0;
    
    if (exitCode == 0 || exitCode == 1) {
        result.success = true;
    } else {
        result.success = false;
        result.errorMessage = QString("ClamAV scan failed (exit code: %1)").arg(exitCode);
        if (!errorOutput.isEmpty()) {
            result.errorMessage += ": " + errorOutput.trimmed();
        }
        return result;
    }
    
    QRegularExpression scannedRegex(R"(Scanned files:\s*(\d+))");
    QRegularExpression infectedRegex(R"(Infected files:\s*(\d+))");
    QRegularExpression threatRegex(R"((.+):\s*(.+)\s*FOUND)");
    
    QRegularExpressionMatch match;
    QStringList infectedFiles;
    
    match = scannedRegex.match(output);
    if (match.hasMatch()) {
        result.filesScanned = match.captured(1).toInt();
    }
    
    match = infectedRegex.match(output);
    if (match.hasMatch()) {
        result.threatsFound = match.captured(1).toInt();
    }
    
    QRegularExpressionMatchIterator i = threatRegex.globalMatch(output);
    while (i.hasNext()) {
        match = i.next();
        QString filePath = match.captured(1).trimmed();
        QString threat = QString("%1: %2").arg(filePath, match.captured(2));
        result.threats << threat;
        infectedFiles << filePath;
    }
    
    if (exitCode == 1 && result.threatsFound == 0) {
        QStringList lines = output.split('\n', Qt::SkipEmptyParts);
        for (const QString& line : lines) {
            if (line.contains("FOUND")) {
                result.threats << line.trimmed();
                result.threatsFound++;
                
                int colonPos = line.indexOf(':');
                if (colonPos > 0) {
                    infectedFiles << line.left(colonPos).trimmed();
                }
            }
        }
    }
    
    if (result.filesScanned == 0 && exitCode == 0) {
        result.filesScanned = 1;
    }
    
    if (autoQuarantine && !infectedFiles.isEmpty()) {
        Logger::getInstance().log(Logger::WARNING, 
            QString("Found %1 infected file(s). Quarantining...").arg(infectedFiles.size()));
        
        for (const QString& infectedFile : infectedFiles) {
            QString quarantinedPath = quarantineFile(infectedFile);
            if (!quarantinedPath.isEmpty()) {
                result.quarantinedFiles << quarantinedPath;
            }
        }
    }
    
    Logger::getInstance().log(Logger::INFO, 
        QString("Scan complete: %1 files, %2 threats, %3 quarantined")
            .arg(result.filesScanned).arg(result.threatsFound).arg(result.quarantinedFiles.size()));
    
    return result;
}

bool VirusScanner::updateDefinitions() {
    if (!clamavAvailable) return false;
    
    QProcess process;
    process.start("freshclam", QStringList());
    
    if (!process.waitForFinished(300000)) {
        Logger::getInstance().log(Logger::ERROR_LEVEL, "Failed to update virus definitions");
        return false;
    }
    
    if (process.exitCode() == 0) {
        Logger::getInstance().log(Logger::SUCCESS, "Virus definitions updated successfully");
        return true;
    }
    
    Logger::getInstance().log(Logger::WARNING, "Could not update virus definitions");
    return false;
}

bool VirusScanner::ensureQuarantineDir() {
    QDir dir(QUARANTINE_DIR);
    if (!dir.exists()) {
        if (!dir.mkpath(".")) {
            Logger::getInstance().log(Logger::ERROR_LEVEL, "Failed to create quarantine directory");
            return false;
        }
        Logger::getInstance().log(Logger::INFO, QString("Created quarantine directory: %1").arg(QUARANTINE_DIR));
    }
    return true;
}

bool VirusScanner::stripExecutablePermissions(const QString& filePath) {
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists()) {
        return false;
    }
    
    struct stat st;
    if (stat(filePath.toStdString().c_str(), &st) != 0) {
        return false;
    }
    
    mode_t newMode = st.st_mode & ~(S_IXUSR | S_IXGRP | S_IXOTH);
    if (chmod(filePath.toStdString().c_str(), newMode) == 0) {
        Logger::getInstance().log(Logger::SUCCESS, QString("Stripped executable permissions from: %1").arg(filePath));
        return true;
    }
    return false;
}

QString VirusScanner::quarantineFile(const QString& filePath) {
    if (!ensureQuarantineDir()) {
        return QString();
    }
    
    QFileInfo fileInfo(filePath);
    QString filename = fileInfo.fileName();
    
    qint64 timestamp = QDateTime::currentSecsSinceEpoch();
    QString quarantinePath = QString("%1/%2_%3.quarantine").arg(QUARANTINE_DIR).arg(timestamp).arg(filename);
    
    stripExecutablePermissions(filePath);
    
    QFile file(filePath);
    if (file.rename(quarantinePath)) {
        Logger::getInstance().log(Logger::SUCCESS, QString("Quarantined file: %1 -> %2").arg(filePath, quarantinePath));
        return quarantinePath;
    } else {
        Logger::getInstance().log(Logger::ERROR_LEVEL, QString("Failed to quarantine file: %1").arg(filePath));
        return QString();
    }
}
