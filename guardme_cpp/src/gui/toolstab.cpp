#include "gui/toolstab.h"
#include "core/configmanager.h"
#include "core/logger.h"
#include "security/urlanalyzer.h"
#include "security/virusscanner.h"
#include "security/whoisanalyzer.h"
#include "network/breachcheck.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QScrollArea>
#include <QFrame>
#include <QFileDialog>
#include <QMessageBox>
#include <QClipboard>
#include <QApplication>
#include <QRandomGenerator>

ToolsTab::ToolsTab(QWidget *parent) : QWidget(parent) {
    setupUI();
    loadWhitelist();
}

void ToolsTab::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    
    QScrollArea *scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    
    QWidget *contentWidget = new QWidget();
    QVBoxLayout *contentLayout = new QVBoxLayout(contentWidget);
    contentLayout->setSpacing(20);
    
    QLabel *titleLabel = new QLabel("Security Tools");
    titleLabel->setStyleSheet("font-size: 24px; font-weight: bold; color: #4a90d9;");
    contentLayout->addWidget(titleLabel);
    
    QGroupBox *urlGroup = new QGroupBox("URL Analysis");
    QVBoxLayout *urlLayout = new QVBoxLayout(urlGroup);
    
    QHBoxLayout *urlInputLayout = new QHBoxLayout();
    urlInput = new QLineEdit();
    urlInput->setPlaceholderText("Enter URL to analyze (e.g., https://example.com)");
    QPushButton *analyzeBtn = new QPushButton("Analyze URL");
    connect(analyzeBtn, &QPushButton::clicked, this, &ToolsTab::analyzeUrl);
    urlInputLayout->addWidget(urlInput);
    urlInputLayout->addWidget(analyzeBtn);
    
    urlThreatLabel = new QLabel("Threat Level: Unknown");
    urlThreatLabel->setStyleSheet("font-weight: bold; padding: 10px;");
    
    urlResultsText = new QTextEdit();
    urlResultsText->setReadOnly(true);
    urlResultsText->setMaximumHeight(150);
    urlResultsText->setPlaceholderText("Analysis results will appear here...");
    
    urlLayout->addLayout(urlInputLayout);
    urlLayout->addWidget(urlThreatLabel);
    urlLayout->addWidget(urlResultsText);
    contentLayout->addWidget(urlGroup);
    
    QGroupBox *whitelistGroup = new QGroupBox("Domain Whitelist");
    QVBoxLayout *whitelistLayout = new QVBoxLayout(whitelistGroup);
    
    QHBoxLayout *whitelistInputLayout = new QHBoxLayout();
    whitelistInput = new QLineEdit();
    whitelistInput->setPlaceholderText("Enter domain (e.g., example.com)");
    QPushButton *addBtn = new QPushButton("Add");
    QPushButton *removeBtn = new QPushButton("Remove Selected");
    connect(addBtn, &QPushButton::clicked, this, &ToolsTab::addToWhitelist);
    connect(removeBtn, &QPushButton::clicked, this, &ToolsTab::removeFromWhitelist);
    whitelistInputLayout->addWidget(whitelistInput);
    whitelistInputLayout->addWidget(addBtn);
    whitelistInputLayout->addWidget(removeBtn);
    
    whitelistList = new QListWidget();
    whitelistList->setMaximumHeight(120);
    
    whitelistLayout->addLayout(whitelistInputLayout);
    whitelistLayout->addWidget(whitelistList);
    contentLayout->addWidget(whitelistGroup);
    
    QGroupBox *breachGroup = new QGroupBox("Breach Checking");
    QVBoxLayout *breachLayout = new QVBoxLayout(breachGroup);
    
    QHBoxLayout *emailInputLayout = new QHBoxLayout();
    emailInput = new QLineEdit();
    emailInput->setPlaceholderText("Enter email address");
    QPushButton *emailCheckBtn = new QPushButton("Check Email Breaches");
    connect(emailCheckBtn, &QPushButton::clicked, this, &ToolsTab::checkEmailBreach);
    emailInputLayout->addWidget(emailInput);
    emailInputLayout->addWidget(emailCheckBtn);
    
    emailResultsText = new QTextEdit();
    emailResultsText->setReadOnly(true);
    emailResultsText->setMaximumHeight(100);
    
    QHBoxLayout *passwordInputLayout = new QHBoxLayout();
    passwordInput = new QLineEdit();
    passwordInput->setPlaceholderText("Enter password to check");
    passwordInput->setEchoMode(QLineEdit::Password);
    QPushButton *passwordCheckBtn = new QPushButton("Check Password");
    connect(passwordCheckBtn, &QPushButton::clicked, this, &ToolsTab::checkPasswordBreach);
    passwordInputLayout->addWidget(passwordInput);
    passwordInputLayout->addWidget(passwordCheckBtn);
    
    passwordResultLabel = new QLabel("Password check result will appear here");
    
    breachLayout->addLayout(emailInputLayout);
    breachLayout->addWidget(emailResultsText);
    breachLayout->addLayout(passwordInputLayout);
    breachLayout->addWidget(passwordResultLabel);
    contentLayout->addWidget(breachGroup);
    
    QGroupBox *virusGroup = new QGroupBox("Virus Scanner");
    QVBoxLayout *virusLayout = new QVBoxLayout(virusGroup);
    
    QHBoxLayout *scanInputLayout = new QHBoxLayout();
    scanPathInput = new QLineEdit();
    scanPathInput->setPlaceholderText("Select file or folder to scan");
    QPushButton *browseFileBtn = new QPushButton("Browse Files");
    QPushButton *browseFolderBtn = new QPushButton("Browse Folders");
    QPushButton *scanBtn = new QPushButton("Start Scan");
    connect(browseFileBtn, &QPushButton::clicked, [this]() {
        QString path = QFileDialog::getOpenFileName(this, "Select File to Scan");
        if (!path.isEmpty()) scanPathInput->setText(path);
    });
    connect(browseFolderBtn, &QPushButton::clicked, [this]() {
        QString path = QFileDialog::getExistingDirectory(this, "Select Folder to Scan");
        if (!path.isEmpty()) scanPathInput->setText(path);
    });
    connect(scanBtn, &QPushButton::clicked, this, &ToolsTab::startVirusScan);
    scanInputLayout->addWidget(scanPathInput);
    scanInputLayout->addWidget(browseFileBtn);
    scanInputLayout->addWidget(browseFolderBtn);
    scanInputLayout->addWidget(scanBtn);
    
    scanProgress = new QProgressBar();
    scanProgress->setVisible(false);
    
    scanResultsText = new QTextEdit();
    scanResultsText->setReadOnly(true);
    scanResultsText->setMaximumHeight(100);
    
    virusLayout->addLayout(scanInputLayout);
    virusLayout->addWidget(scanProgress);
    virusLayout->addWidget(scanResultsText);
    contentLayout->addWidget(virusGroup);
    
    QGroupBox *whoisGroup = new QGroupBox("WHOIS Lookup");
    QVBoxLayout *whoisLayout = new QVBoxLayout(whoisGroup);
    
    QHBoxLayout *whoisInputLayout = new QHBoxLayout();
    whoisInput = new QLineEdit();
    whoisInput->setPlaceholderText("Enter domain for WHOIS lookup");
    QPushButton *whoisBtn = new QPushButton("Lookup");
    connect(whoisBtn, &QPushButton::clicked, this, &ToolsTab::performWhoisLookup);
    whoisInputLayout->addWidget(whoisInput);
    whoisInputLayout->addWidget(whoisBtn);
    
    whoisResultsText = new QTextEdit();
    whoisResultsText->setReadOnly(true);
    whoisResultsText->setMaximumHeight(150);
    
    whoisLayout->addLayout(whoisInputLayout);
    whoisLayout->addWidget(whoisResultsText);
    contentLayout->addWidget(whoisGroup);
    
    QGroupBox *passwordGenGroup = new QGroupBox("Password Generator");
    QVBoxLayout *passwordGenLayout = new QVBoxLayout(passwordGenGroup);
    
    QLabel *passwordGenLabel = new QLabel("Generate a secure 8-character password:");
    
    QHBoxLayout *passwordGenInputLayout = new QHBoxLayout();
    generatedPasswordDisplay = new QLineEdit();
    generatedPasswordDisplay->setReadOnly(true);
    generatedPasswordDisplay->setPlaceholderText("Click 'Generate' to create a password");
    generatedPasswordDisplay->setStyleSheet("font-family: monospace; font-size: 16px; font-weight: bold;");
    
    QPushButton *generateBtn = new QPushButton("Generate");
    QPushButton *copyBtn = new QPushButton("Copy to Clipboard");
    connect(generateBtn, &QPushButton::clicked, this, &ToolsTab::generatePassword);
    connect(copyBtn, &QPushButton::clicked, this, &ToolsTab::copyPasswordToClipboard);
    
    passwordGenInputLayout->addWidget(generatedPasswordDisplay);
    passwordGenInputLayout->addWidget(generateBtn);
    passwordGenInputLayout->addWidget(copyBtn);
    
    passwordGenLayout->addWidget(passwordGenLabel);
    passwordGenLayout->addLayout(passwordGenInputLayout);
    contentLayout->addWidget(passwordGenGroup);
    
    contentLayout->addStretch();
    
    scrollArea->setWidget(contentWidget);
    mainLayout->addWidget(scrollArea);
}

void ToolsTab::loadWhitelist() {
    whitelistList->clear();
    for (const QString& domain : ConfigManager::getInstance().getWhitelistedDomains()) {
        whitelistList->addItem(domain);
    }
}

void ToolsTab::analyzeUrl() {
    QString url = urlInput->text().trimmed();
    if (url.isEmpty()) {
        QMessageBox::warning(this, "Input Required", "Please enter a URL to analyze.");
        return;
    }
    
    UrlAnalyzer& analyzer = UrlAnalyzer::getInstance();
    UrlAnalyzer::AnalysisResult result = analyzer.analyzeUrl(url);
    
    QString threatColor;
    switch (result.threatLevel) {
        case UrlAnalyzer::SAFE: threatColor = "#2ecc71"; break;
        case UrlAnalyzer::LOW: threatColor = "#f1c40f"; break;
        case UrlAnalyzer::MEDIUM: threatColor = "#e67e22"; break;
        case UrlAnalyzer::HIGH: threatColor = "#e74c3c"; break;
        case UrlAnalyzer::CRITICAL: threatColor = "#c0392b"; break;
    }
    
    urlThreatLabel->setText(QString("Threat Level: %1 (Score: %2/100)")
        .arg(result.threatLevelString).arg(result.score));
    urlThreatLabel->setStyleSheet(QString("font-weight: bold; padding: 10px; color: %1;").arg(threatColor));
    
    QString details;
    details += QString("URL: %1\n\n").arg(url);
    details += QString("Risk Score: %1/100\n").arg(result.score);
    details += QString("Threat Level: %1\n\n").arg(result.threatLevelString);
    details += "Analysis Details:\n";
    for (const QString& detail : result.details) {
        details += QString("- %1\n").arg(detail);
    }
    
    urlResultsText->setText(details);
    Logger::getInstance().log(Logger::INFO, QString("URL analyzed: %1 - %2").arg(url, result.threatLevelString));
}

void ToolsTab::checkEmailBreach() {
    QString email = emailInput->text().trimmed();
    if (email.isEmpty()) {
        QMessageBox::warning(this, "Input Required", "Please enter an email address.");
        return;
    }
    
    emailResultsText->setText("Checking email for breaches...");
    
    BreachCheck& checker = BreachCheck::getInstance();
    BreachCheck::BreachResult result = checker.checkEmail(email);
    
    QString text;
    if (result.found) {
        text = QString("WARNING: Email found in %1 breach(es)!\n\n").arg(result.breachCount);
        text += "Breached sites:\n";
        for (const QString& site : result.breachedSites) {
            text += QString("- %1\n").arg(site);
        }
        text += "\nRecommendation: Change passwords for affected sites.";
        emailResultsText->setStyleSheet("color: #e74c3c;");
    } else {
        text = "Good news! No breaches found for this email address.";
        emailResultsText->setStyleSheet("color: #2ecc71;");
    }
    
    emailResultsText->setText(text);
}

void ToolsTab::checkPasswordBreach() {
    QString password = passwordInput->text();
    if (password.isEmpty()) {
        QMessageBox::warning(this, "Input Required", "Please enter a password to check.");
        return;
    }
    
    BreachCheck& checker = BreachCheck::getInstance();
    BreachCheck::PasswordResult result = checker.checkPassword(password);
    
    if (result.pwned) {
        passwordResultLabel->setText(QString("DANGER: Password found in %1 breaches!")
            .arg(result.occurrences));
        passwordResultLabel->setStyleSheet("color: #e74c3c; font-weight: bold; padding: 10px;");
    } else {
        passwordResultLabel->setText("Password not found in known breaches.");
        passwordResultLabel->setStyleSheet("color: #2ecc71; font-weight: bold; padding: 10px;");
    }
    
    passwordInput->clear();
}

void ToolsTab::addToWhitelist() {
    QString domain = whitelistInput->text().trimmed().toLower();
    if (domain.isEmpty()) return;
    
    domain = domain.replace("http://", "").replace("https://", "").split("/").first();
    
    ConfigManager::getInstance().addWhitelistedDomain(domain);
    loadWhitelist();
    whitelistInput->clear();
}

void ToolsTab::removeFromWhitelist() {
    QListWidgetItem *item = whitelistList->currentItem();
    if (!item) {
        QMessageBox::warning(this, "Selection Required", "Please select a domain to remove.");
        return;
    }
    
    ConfigManager::getInstance().removeWhitelistedDomain(item->text());
    loadWhitelist();
}

void ToolsTab::startVirusScan() {
    QString path = scanPathInput->text().trimmed();
    if (path.isEmpty()) {
        QMessageBox::warning(this, "Path Required", "Please select a file or folder to scan.");
        return;
    }
    
    VirusScanner& scanner = VirusScanner::getInstance();
    
    if (!scanner.isAvailable()) {
        QMessageBox::critical(this, "Error", 
            "ClamAV is not installed! Please delete this binary and install ClamAV using the setup.sh file.");
        scanResultsText->setText("Error: ClamAV is not installed! Please delete this binary and install ClamAV using the setup.sh file.");
        scanResultsText->setStyleSheet("color: #e74c3c;");
        return;
    }
    
    scanProgress->setVisible(true);
    scanProgress->setRange(0, 0);
    scanResultsText->setText("Scanning...");
    
    VirusScanner::ScanResult result = scanner.scanPath(path);
    
    scanProgress->setVisible(false);
    
    QString text;
    text += QString("Scan Complete\n\n");
    text += QString("Files Scanned: %1\n").arg(result.filesScanned);
    text += QString("Threats Found: %1\n").arg(result.threatsFound);
    text += QString("Scan Time: %1 seconds\n\n").arg(result.scanTime);
    
    if (result.threatsFound > 0) {
        text += "Detected Threats:\n";
        for (const QString& threat : result.threats) {
            text += QString("- %1\n").arg(threat);
        }
        if (!result.quarantinedFiles.isEmpty()) {
            text += "\nQuarantined Files:\n";
            for (const QString& qFile : result.quarantinedFiles) {
                text += QString("-> %1\n").arg(qFile);
            }
            text += "\nAction Taken:\n";
            text += "- Executable permissions removed\n";
            text += QString("- Files moved to quarantine: %1\n").arg(VirusScanner::QUARANTINE_DIR);
        }
        scanResultsText->setStyleSheet("color: #e74c3c;");
    } else {
        text += "No threats detected.";
        scanResultsText->setStyleSheet("color: #2ecc71;");
    }
    
    scanResultsText->setText(text);
}

void ToolsTab::performWhoisLookup() {
    QString domain = whoisInput->text().trimmed();
    if (domain.isEmpty()) {
        QMessageBox::warning(this, "Input Required", "Please enter a domain.");
        return;
    }
    
    whoisResultsText->setText("Looking up WHOIS information...");
    
    WhoisAnalyzer& analyzer = WhoisAnalyzer::getInstance();
    WhoisAnalyzer::WhoisResult result = analyzer.lookup(domain);
    
    QString text;
    text += QString("Domain: %1\n\n").arg(result.domain);
    text += QString("Registrar: %1\n").arg(result.registrar);
    text += QString("Created: %1\n").arg(result.creationDate);
    text += QString("Expires: %1\n").arg(result.expirationDate);
    text += QString("Updated: %1\n").arg(result.updatedDate);
    text += QString("\nDomain Age: %1 days\n").arg(result.domainAge);
    
    if (result.domainAge < 30) {
        text += "\nWARNING: Very new domain - may be suspicious!";
        whoisResultsText->setStyleSheet("color: #e67e22;");
    } else {
        whoisResultsText->setStyleSheet("color: #ffffff;");
    }
    
    whoisResultsText->setText(text);
}

void ToolsTab::generatePassword() {
    const QString chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    QString password;
    
    for (int i = 0; i < 8; ++i) {
        int index = QRandomGenerator::global()->bounded(chars.length());
        password += chars.at(index);
    }
    
    generatedPasswordDisplay->setText(password);
    generatedPasswordDisplay->setStyleSheet("font-family: monospace; font-size: 16px; font-weight: bold; color: #2ecc71;");
    Logger::getInstance().log(Logger::SUCCESS, "Password generated successfully");
}

void ToolsTab::copyPasswordToClipboard() {
    QString password = generatedPasswordDisplay->text();
    if (password.isEmpty()) {
        QMessageBox::warning(this, "No Password", "Please generate a password first.");
        return;
    }
    
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(password);
    
    QMessageBox::information(this, "Copied", "Password copied to clipboard!");
    Logger::getInstance().log(Logger::INFO, "Password copied to clipboard");
}
