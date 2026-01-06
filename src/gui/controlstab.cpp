#include "gui/controlstab.h"
#include "core/configmanager.h"
#include "core/logger.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QLabel>
#include <QFileDialog>
#include <QScrollArea>
#include <QFrame>

ControlsTab::ControlsTab(QWidget *parent) : QWidget(parent) {
    setupUI();
    loadSettings();
}

void ControlsTab::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    
    QScrollArea *scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    
    QWidget *contentWidget = new QWidget();
    QVBoxLayout *contentLayout = new QVBoxLayout(contentWidget);
    contentLayout->setSpacing(20);
    
    QLabel *titleLabel = new QLabel("Security Controls");
    titleLabel->setStyleSheet("font-size: 24px; font-weight: bold; color: #4a90d9;");
    contentLayout->addWidget(titleLabel);
    
    QGroupBox *protectionGroup = new QGroupBox("Protection Modules");
    QVBoxLayout *protectionLayout = new QVBoxLayout(protectionGroup);
    
    urlMonitorCheck = new QCheckBox("Enable URL Monitor");
    urlMonitorCheck->setToolTip("Monitor and analyze URLs for threats in real-time");
    connect(urlMonitorCheck, &QCheckBox::toggled, this, &ControlsTab::toggleUrlMonitor);
    
    downloadMonitorCheck = new QCheckBox("Enable Download Monitor");
    downloadMonitorCheck->setToolTip("Monitor downloads folder and scan new files");
    connect(downloadMonitorCheck, &QCheckBox::toggled, this, &ControlsTab::toggleDownloadMonitor);
    
    virusScanCheck = new QCheckBox("Enable Virus Scanner Integration");
    virusScanCheck->setToolTip("Use ClamAV for virus scanning");
    connect(virusScanCheck, &QCheckBox::toggled, this, &ControlsTab::toggleVirusScanner);
    
    protectionLayout->addWidget(urlMonitorCheck);
    protectionLayout->addWidget(downloadMonitorCheck);
    protectionLayout->addWidget(virusScanCheck);
    contentLayout->addWidget(protectionGroup);
    
    QGroupBox *pathGroup = new QGroupBox("Monitor Paths");
    QVBoxLayout *pathLayout = new QVBoxLayout(pathGroup);
    
    QLabel *downloadLabel = new QLabel("Downloads Folder:");
    QHBoxLayout *downloadPathLayout = new QHBoxLayout();
    downloadsPathEdit = new QLineEdit();
    downloadsPathEdit->setReadOnly(true);
    QPushButton *browseBtn = new QPushButton("Browse Folders");
    connect(browseBtn, &QPushButton::clicked, this, &ControlsTab::browseDownloadsPath);
    
    downloadPathLayout->addWidget(downloadsPathEdit);
    downloadPathLayout->addWidget(browseBtn);
    
    pathLayout->addWidget(downloadLabel);
    pathLayout->addLayout(downloadPathLayout);
    contentLayout->addWidget(pathGroup);
    
    QGroupBox *excludeGroup = new QGroupBox("File Type Exclusions");
    QVBoxLayout *excludeLayout = new QVBoxLayout(excludeGroup);
    
    QLabel *excludeLabel = new QLabel("Excluded extensions (comma-separated):");
    excludedExtEdit = new QLineEdit();
    excludedExtEdit->setPlaceholderText(".txt, .pdf, .doc");
    
    QPushButton *updateExcludeBtn = new QPushButton("Update Exclusions");
    connect(updateExcludeBtn, &QPushButton::clicked, this, &ControlsTab::updateExcludedExtensions);
    
    excludeLayout->addWidget(excludeLabel);
    excludeLayout->addWidget(excludedExtEdit);
    excludeLayout->addWidget(updateExcludeBtn);
    contentLayout->addWidget(excludeGroup);
    
    contentLayout->addStretch();
    
    scrollArea->setWidget(contentWidget);
    mainLayout->addWidget(scrollArea);
}

void ControlsTab::loadSettings() {
    ConfigManager& config = ConfigManager::getInstance();
    
    urlMonitorCheck->setChecked(config.isUrlMonitorEnabled());
    downloadMonitorCheck->setChecked(config.isDownloadMonitorEnabled());
    virusScanCheck->setChecked(config.isVirusScanEnabled());
    downloadsPathEdit->setText(config.getDownloadsPath());
    excludedExtEdit->setText(config.getExcludedExtensions().join(", "));
}

void ControlsTab::toggleUrlMonitor(bool enabled) {
    ConfigManager::getInstance().setUrlMonitorEnabled(enabled);
    Logger::getInstance().log(Logger::INFO, 
        QString("URL Monitor %1").arg(enabled ? "enabled" : "disabled"));
}

void ControlsTab::toggleDownloadMonitor(bool enabled) {
    ConfigManager::getInstance().setDownloadMonitorEnabled(enabled);
    Logger::getInstance().log(Logger::INFO, 
        QString("Download Monitor %1").arg(enabled ? "enabled" : "disabled"));
}

void ControlsTab::toggleVirusScanner(bool enabled) {
    ConfigManager::getInstance().setVirusScanEnabled(enabled);
    Logger::getInstance().log(Logger::INFO, 
        QString("Virus Scanner %1").arg(enabled ? "enabled" : "disabled"));
}

void ControlsTab::browseDownloadsPath() {
    QString dir = QFileDialog::getExistingDirectory(this, "Select Downloads Folder",
        downloadsPathEdit->text(), QFileDialog::ShowDirsOnly);
    
    if (!dir.isEmpty()) {
        downloadsPathEdit->setText(dir);
        ConfigManager::getInstance().setDownloadsPath(dir);
    }
}

void ControlsTab::updateExcludedExtensions() {
    QStringList extensions = excludedExtEdit->text().split(",", Qt::SkipEmptyParts);
    for (QString& ext : extensions) {
        ext = ext.trimmed();
        if (!ext.startsWith(".")) {
            ext.prepend(".");
        }
    }
    ConfigManager::getInstance().setExcludedExtensions(extensions);
    Logger::getInstance().log(Logger::INFO, "Updated file exclusions");
}
