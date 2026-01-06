#ifndef VIRUSSCANNER_H
#define VIRUSSCANNER_H

#include <QString>
#include <QStringList>
#include <QProcess>

class VirusScanner {
public:
    struct ScanResult {
        int filesScanned;
        int threatsFound;
        double scanTime;
        QStringList threats;
        QStringList quarantinedFiles;
        bool success;
        QString errorMessage;
    };
    
    static VirusScanner& getInstance() {
        static VirusScanner instance;
        return instance;
    }
    
    static const QString QUARANTINE_DIR;
    
    bool isAvailable() const { return clamavAvailable; }
    ScanResult scanFile(const QString& filePath);
    ScanResult scanPath(const QString& path, bool autoQuarantine = true);
    bool updateDefinitions();
    
    static bool ensureQuarantineDir();
    static bool stripExecutablePermissions(const QString& filePath);
    static QString quarantineFile(const QString& filePath);
    
private:
    VirusScanner();
    ~VirusScanner() = default;
    VirusScanner(const VirusScanner&) = delete;
    VirusScanner& operator=(const VirusScanner&) = delete;
    
    bool checkClamav();
    ScanResult parseClamscanOutput(const QString& output, const QString& errorOutput, int exitCode, bool autoQuarantine = true);
    
    bool clamavAvailable;
    QString clamscanPath;
};

#endif
