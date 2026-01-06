#ifndef DOWNLOADMONITOR_H
#define DOWNLOADMONITOR_H

#include <QObject>
#include <QFileSystemWatcher>
#include <QString>
#include <QStringList>
#include <QSet>

class DownloadMonitor : public QObject {
    Q_OBJECT

public:
    static DownloadMonitor& getInstance() {
        static DownloadMonitor instance;
        return instance;
    }
    
    void startMonitoring(const QString& path);
    void stopMonitoring();
    bool isMonitoring() const { return monitoring; }
    
signals:
    void newFileDetected(const QString& filePath);
    void threatDetected(const QString& filePath, const QString& threat);
    void fileSafe(const QString& filePath);

private slots:
    void onDirectoryChanged(const QString& path);

private:
    DownloadMonitor();
    ~DownloadMonitor();
    DownloadMonitor(const DownloadMonitor&) = delete;
    DownloadMonitor& operator=(const DownloadMonitor&) = delete;
    
    void processNewFile(const QString& filePath);
    bool isExcludedExtension(const QString& filePath);
    
    QFileSystemWatcher *watcher;
    QString monitoredPath;
    QSet<QString> knownFiles;
    bool monitoring;
};

#endif
