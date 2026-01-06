#ifndef SYSTEMMONITOR_H
#define SYSTEMMONITOR_H

#include <QString>
#include <QTimer>

class SystemMonitor {
public:
    static SystemMonitor& getInstance() {
        static SystemMonitor instance;
        return instance;
    }
    
    int getCpuUsage();
    int getMemoryUsage();
    int getDiskUsage();
    QString getSystemInfo();
    
private:
    SystemMonitor();
    ~SystemMonitor() = default;
    SystemMonitor(const SystemMonitor&) = delete;
    SystemMonitor& operator=(const SystemMonitor&) = delete;
    
    void updateCpuUsage();
    
    long long prevIdle;
    long long prevTotal;
    int cachedCpuUsage;
};

#endif
