#ifndef DASHBOARDTAB_H
#define DASHBOARDTAB_H

#include <QWidget>
#include <QLabel>
#include <QProgressBar>
#include <QTimer>
#include <QGridLayout>

class DashboardTab : public QWidget {
    Q_OBJECT

public:
    explicit DashboardTab(QWidget *parent = nullptr);

private slots:
    void updateStats();

private:
    void setupUI();
    QWidget* createStatusCard(const QString& title, const QString& value, const QString& color);
    QWidget* createProtectionWidget();
    QWidget* createThreatSummaryWidget();
    QWidget* createSystemHealthWidget();
    
    QLabel *urlsScannedLabel;
    QLabel *threatsBlockedLabel;
    QLabel *downloadsMonitoredLabel;
    QLabel *emailsCheckedLabel;
    QLabel *protectionStatusLabel;
    QProgressBar *cpuUsageBar;
    QProgressBar *memoryUsageBar;
    QProgressBar *diskUsageBar;
    QTimer *updateTimer;
    
    int urlsScanned;
    int threatsBlocked;
    int downloadsMonitored;
    int emailsChecked;
};

#endif
