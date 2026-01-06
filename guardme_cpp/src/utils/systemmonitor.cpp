#include "utils/systemmonitor.h"
#include <QFile>
#include <QTextStream>
#include <QStorageInfo>
#include <QSysInfo>

SystemMonitor::SystemMonitor() : prevIdle(0), prevTotal(0), cachedCpuUsage(0) {
}

int SystemMonitor::getCpuUsage() {
#ifdef Q_OS_LINUX
    QFile file("/proc/stat");
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return cachedCpuUsage;
    }
    
    QTextStream stream(&file);
    QString line = stream.readLine();
    file.close();
    
    if (!line.startsWith("cpu ")) {
        return cachedCpuUsage;
    }
    
    QStringList parts = line.split(' ', Qt::SkipEmptyParts);
    if (parts.size() < 5) {
        return cachedCpuUsage;
    }
    
    long long user = parts[1].toLongLong();
    long long nice = parts[2].toLongLong();
    long long system = parts[3].toLongLong();
    long long idle = parts[4].toLongLong();
    long long iowait = parts.size() > 5 ? parts[5].toLongLong() : 0;
    
    long long total = user + nice + system + idle + iowait;
    long long totalIdle = idle + iowait;
    
    if (prevTotal > 0) {
        long long diffTotal = total - prevTotal;
        long long diffIdle = totalIdle - prevIdle;
        
        if (diffTotal > 0) {
            cachedCpuUsage = 100 * (diffTotal - diffIdle) / diffTotal;
        }
    }
    
    prevTotal = total;
    prevIdle = totalIdle;
    
    return qBound(0, cachedCpuUsage, 100);
#else
    return 0;
#endif
}

int SystemMonitor::getMemoryUsage() {
#ifdef Q_OS_LINUX
    QFile file("/proc/meminfo");
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return 0;
    }
    
    QTextStream stream(&file);
    QString content = stream.readAll();
    file.close();
    
    long long total = 0, available = 0;
    
    QStringList lines = content.split('\n');
    for (const QString& line : lines) {
        if (line.startsWith("MemTotal:")) {
            QStringList parts = line.split(' ', Qt::SkipEmptyParts);
            if (parts.size() >= 2) {
                total = parts[1].toLongLong();
            }
        } else if (line.startsWith("MemAvailable:")) {
            QStringList parts = line.split(' ', Qt::SkipEmptyParts);
            if (parts.size() >= 2) {
                available = parts[1].toLongLong();
            }
        }
    }
    
    if (total > 0) {
        return 100 * (total - available) / total;
    }
    
    return 0;
#else
    return 0;
#endif
}

int SystemMonitor::getDiskUsage() {
    QStorageInfo storage = QStorageInfo::root();
    
    if (storage.isValid() && storage.bytesTotal() > 0) {
        long long used = storage.bytesTotal() - storage.bytesAvailable();
        return 100 * used / storage.bytesTotal();
    }
    
    return 0;
}

QString SystemMonitor::getSystemInfo() {
    QString info;
    info += QString("OS: %1\n").arg(QSysInfo::prettyProductName());
    info += QString("Kernel: %1\n").arg(QSysInfo::kernelVersion());
    info += QString("Architecture: %1\n").arg(QSysInfo::currentCpuArchitecture());
    info += QString("CPU Usage: %1%\n").arg(getCpuUsage());
    info += QString("Memory Usage: %1%\n").arg(getMemoryUsage());
    info += QString("Disk Usage: %1%\n").arg(getDiskUsage());
    
    return info;
}
