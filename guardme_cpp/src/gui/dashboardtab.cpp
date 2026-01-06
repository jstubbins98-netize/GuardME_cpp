#include "gui/dashboardtab.h"
#include "utils/systemmonitor.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFrame>
#include <QScrollArea>

DashboardTab::DashboardTab(QWidget *parent) 
    : QWidget(parent), urlsScanned(0), threatsBlocked(0), 
      downloadsMonitored(0), emailsChecked(0) {
    
    setupUI();
    
    updateTimer = new QTimer(this);
    connect(updateTimer, &QTimer::timeout, this, &DashboardTab::updateStats);
    updateTimer->start(2000);
}

void DashboardTab::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(20);
    
    QScrollArea *scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    
    QWidget *contentWidget = new QWidget();
    QVBoxLayout *contentLayout = new QVBoxLayout(contentWidget);
    contentLayout->setSpacing(20);
    
    QLabel *titleLabel = new QLabel("Security Dashboard");
    titleLabel->setStyleSheet("font-size: 24px; font-weight: bold; color: #4a90d9;");
    contentLayout->addWidget(titleLabel);
    
    QHBoxLayout *statsLayout = new QHBoxLayout();
    statsLayout->setSpacing(15);
    
    urlsScannedLabel = new QLabel("0");
    threatsBlockedLabel = new QLabel("0");
    downloadsMonitoredLabel = new QLabel("0");
    emailsCheckedLabel = new QLabel("0");
    
    statsLayout->addWidget(createStatusCard("URLs Scanned", "0", "#4a90d9"));
    statsLayout->addWidget(createStatusCard("Threats Blocked", "0", "#e74c3c"));
    statsLayout->addWidget(createStatusCard("Downloads Monitored", "0", "#2ecc71"));
    statsLayout->addWidget(createStatusCard("Emails Checked", "0", "#f39c12"));
    
    contentLayout->addLayout(statsLayout);
    
    QHBoxLayout *widgetsLayout = new QHBoxLayout();
    widgetsLayout->setSpacing(15);
    
    widgetsLayout->addWidget(createProtectionWidget());
    widgetsLayout->addWidget(createThreatSummaryWidget());
    widgetsLayout->addWidget(createSystemHealthWidget());
    
    contentLayout->addLayout(widgetsLayout);
    contentLayout->addStretch();
    
    scrollArea->setWidget(contentWidget);
    mainLayout->addWidget(scrollArea);
}

QWidget* DashboardTab::createStatusCard(const QString& title, const QString& value, const QString& color) {
    QFrame *card = new QFrame();
    card->setStyleSheet(QString(R"(
        QFrame {
            background-color: #3c3c3c;
            border-radius: 8px;
            padding: 15px;
        }
    )"));
    card->setMinimumHeight(120);
    
    QVBoxLayout *layout = new QVBoxLayout(card);
    
    QLabel *titleLabel = new QLabel(title);
    titleLabel->setStyleSheet("color: #888888; font-size: 12px;");
    
    QLabel *valueLabel = new QLabel(value);
    valueLabel->setStyleSheet(QString("color: %1; font-size: 36px; font-weight: bold;").arg(color));
    valueLabel->setObjectName(title);
    
    layout->addWidget(titleLabel);
    layout->addWidget(valueLabel);
    layout->addStretch();
    
    return card;
}

QWidget* DashboardTab::createProtectionWidget() {
    QGroupBox *group = new QGroupBox("Protection Status");
    QVBoxLayout *layout = new QVBoxLayout(group);
    
    protectionStatusLabel = new QLabel("ACTIVE");
    protectionStatusLabel->setStyleSheet(R"(
        QLabel {
            color: #2ecc71;
            font-size: 24px;
            font-weight: bold;
            padding: 20px;
            background-color: rgba(46, 204, 113, 0.2);
            border-radius: 8px;
        }
    )");
    protectionStatusLabel->setAlignment(Qt::AlignCenter);
    
    layout->addWidget(protectionStatusLabel);
    
    QLabel *detailsLabel = new QLabel(
        "All security modules running\n"
        "URL Monitor: Active\n"
        "Download Protection: Active\n"
        "Virus Scanner: Ready"
    );
    detailsLabel->setStyleSheet("color: #aaaaaa; padding: 10px;");
    layout->addWidget(detailsLabel);
    
    layout->addStretch();
    
    return group;
}

QWidget* DashboardTab::createThreatSummaryWidget() {
    QGroupBox *group = new QGroupBox("Recent Threat Activity");
    QVBoxLayout *layout = new QVBoxLayout(group);
    
    QLabel *summaryLabel = new QLabel(
        "Last 24 Hours:\n\n"
        "Malicious URLs blocked: 0\n"
        "Suspicious downloads: 0\n"
        "Phishing attempts: 0\n"
        "Malware detected: 0"
    );
    summaryLabel->setStyleSheet("color: #ffffff; padding: 10px; line-height: 1.5;");
    
    layout->addWidget(summaryLabel);
    layout->addStretch();
    
    return group;
}

QWidget* DashboardTab::createSystemHealthWidget() {
    QGroupBox *group = new QGroupBox("System Health");
    QVBoxLayout *layout = new QVBoxLayout(group);
    
    QLabel *cpuLabel = new QLabel("CPU Usage:");
    cpuUsageBar = new QProgressBar();
    cpuUsageBar->setRange(0, 100);
    cpuUsageBar->setValue(0);
    cpuUsageBar->setFormat("%p%");
    
    QLabel *memLabel = new QLabel("Memory Usage:");
    memoryUsageBar = new QProgressBar();
    memoryUsageBar->setRange(0, 100);
    memoryUsageBar->setValue(0);
    memoryUsageBar->setFormat("%p%");
    
    QLabel *diskLabel = new QLabel("Disk Usage:");
    diskUsageBar = new QProgressBar();
    diskUsageBar->setRange(0, 100);
    diskUsageBar->setValue(0);
    diskUsageBar->setFormat("%p%");
    
    layout->addWidget(cpuLabel);
    layout->addWidget(cpuUsageBar);
    layout->addWidget(memLabel);
    layout->addWidget(memoryUsageBar);
    layout->addWidget(diskLabel);
    layout->addWidget(diskUsageBar);
    layout->addStretch();
    
    return group;
}

void DashboardTab::updateStats() {
    cpuUsageBar->setValue(SystemMonitor::getInstance().getCpuUsage());
    memoryUsageBar->setValue(SystemMonitor::getInstance().getMemoryUsage());
    diskUsageBar->setValue(SystemMonitor::getInstance().getDiskUsage());
}
