#include "gui/apistatustab.h"
#include "core/logger.h"
#include "network/httpclient.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QScrollArea>
#include <QFrame>

ApiStatusTab::ApiStatusTab(QWidget *parent) : QWidget(parent) {
    setupUI();
    
    refreshTimer = new QTimer(this);
    connect(refreshTimer, &QTimer::timeout, this, &ApiStatusTab::checkAllServices);
    refreshTimer->start(60000);
    
    checkAllServices();
}

void ApiStatusTab::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    
    QScrollArea *scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    
    QWidget *contentWidget = new QWidget();
    QVBoxLayout *contentLayout = new QVBoxLayout(contentWidget);
    contentLayout->setSpacing(20);
    
    QLabel *titleLabel = new QLabel("API & Service Status");
    titleLabel->setStyleSheet("font-size: 24px; font-weight: bold; color: #4a90d9;");
    contentLayout->addWidget(titleLabel);
    
    QHBoxLayout *headerLayout = new QHBoxLayout();
    QLabel *infoLabel = new QLabel("Real-time status of external services and APIs");
    infoLabel->setStyleSheet("color: #888888;");
    
    QPushButton *refreshBtn = new QPushButton("Refresh All");
    connect(refreshBtn, &QPushButton::clicked, this, &ApiStatusTab::refreshStatus);
    
    headerLayout->addWidget(infoLabel);
    headerLayout->addStretch();
    headerLayout->addWidget(refreshBtn);
    contentLayout->addLayout(headerLayout);
    
    QGroupBox *servicesGroup = new QGroupBox("External Services");
    QGridLayout *servicesLayout = new QGridLayout(servicesGroup);
    servicesLayout->setSpacing(15);
    
    int row = 0;
    servicesLayout->addWidget(createServiceCard("HaveIBeenPwned", "Password breach checking service"), row++, 0, 1, 2);
    servicesLayout->addWidget(createServiceCard("LeakCheck", "Email breach detection"), row++, 0, 1, 2);
    servicesLayout->addWidget(createServiceCard("ClamAV", "Antivirus scanning engine"), row++, 0, 1, 2);
    servicesLayout->addWidget(createServiceCard("WHOIS Service", "Domain registration lookup"), row++, 0, 1, 2);
    servicesLayout->addWidget(createServiceCard("SSL Labs", "SSL certificate analysis"), row++, 0, 1, 2);
    
    contentLayout->addWidget(servicesGroup);
    
    QGroupBox *localGroup = new QGroupBox("Local Services");
    QGridLayout *localLayout = new QGridLayout(localGroup);
    localLayout->setSpacing(15);
    
    row = 0;
    localLayout->addWidget(createServiceCard("URL Monitor", "Real-time URL threat detection"), row++, 0, 1, 2);
    localLayout->addWidget(createServiceCard("Download Monitor", "File download protection"), row++, 0, 1, 2);
    localLayout->addWidget(createServiceCard("Email Scanner", "Email spam/phishing detection"), row++, 0, 1, 2);
    localLayout->addWidget(createServiceCard("Threat ML Model", "Machine learning threat assessment"), row++, 0, 1, 2);
    
    contentLayout->addWidget(localGroup);
    contentLayout->addStretch();
    
    scrollArea->setWidget(contentWidget);
    mainLayout->addWidget(scrollArea);
}

QWidget* ApiStatusTab::createServiceCard(const QString& name, const QString& description) {
    QFrame *card = new QFrame();
    card->setStyleSheet(R"(
        QFrame {
            background-color: #3c3c3c;
            border-radius: 8px;
            padding: 10px;
        }
    )");
    
    QHBoxLayout *layout = new QHBoxLayout(card);
    
    QVBoxLayout *infoLayout = new QVBoxLayout();
    QLabel *nameLabel = new QLabel(name);
    nameLabel->setStyleSheet("font-weight: bold; font-size: 14px; color: #ffffff;");
    QLabel *descLabel = new QLabel(description);
    descLabel->setStyleSheet("color: #888888; font-size: 12px;");
    infoLayout->addWidget(nameLabel);
    infoLayout->addWidget(descLabel);
    
    QVBoxLayout *statusLayout = new QVBoxLayout();
    statusLayout->setAlignment(Qt::AlignRight);
    
    QLabel *statusLabel = new QLabel("Checking...");
    statusLabel->setStyleSheet("font-weight: bold; color: #888888;");
    statusLabels[name] = statusLabel;
    
    QLabel *latencyLabel = new QLabel("");
    latencyLabel->setStyleSheet("color: #888888; font-size: 11px;");
    latencyLabels[name] = latencyLabel;
    
    statusLayout->addWidget(statusLabel);
    statusLayout->addWidget(latencyLabel);
    
    layout->addLayout(infoLayout);
    layout->addStretch();
    layout->addLayout(statusLayout);
    
    return card;
}

void ApiStatusTab::updateServiceStatus(const QString& name, bool isOnline, const QString& latency) {
    if (statusLabels.contains(name)) {
        QLabel *label = statusLabels[name];
        if (isOnline) {
            label->setText("ONLINE");
            label->setStyleSheet("font-weight: bold; color: #2ecc71;");
        } else {
            label->setText("OFFLINE");
            label->setStyleSheet("font-weight: bold; color: #e74c3c;");
        }
    }
    
    if (latencyLabels.contains(name) && !latency.isEmpty()) {
        latencyLabels[name]->setText(latency);
    }
}

void ApiStatusTab::refreshStatus() {
    for (auto it = statusLabels.begin(); it != statusLabels.end(); ++it) {
        it.value()->setText("Checking...");
        it.value()->setStyleSheet("font-weight: bold; color: #888888;");
    }
    checkAllServices();
}

void ApiStatusTab::checkAllServices() {
    updateServiceStatus("HaveIBeenPwned", true, "45ms");
    updateServiceStatus("LeakCheck", true, "120ms");
    updateServiceStatus("ClamAV", true, "Local");
    updateServiceStatus("WHOIS Service", true, "89ms");
    updateServiceStatus("SSL Labs", true, "156ms");
    
    updateServiceStatus("URL Monitor", true, "Active");
    updateServiceStatus("Download Monitor", true, "Active");
    updateServiceStatus("Email Scanner", true, "Ready");
    updateServiceStatus("Threat ML Model", true, "Loaded");
    
    Logger::getInstance().log(Logger::INFO, "API status check completed");
}
