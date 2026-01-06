#include "gui/emailprotectiontab.h"
#include "security/credentialvault.h"
#include "core/logger.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QScrollArea>
#include <QFrame>
#include <QMessageBox>
#include <QSplitter>
#include <QPixmap>
#include <QtConcurrent>
#include <QInputDialog>

EmailProtectionTab::EmailProtectionTab(QWidget *parent) 
    : QWidget(parent), currentWizardStep(0) {
    connectionWatcher = new QFutureWatcher<bool>(this);
    testConnectionWatcher = new QFutureWatcher<bool>(this);
    resetConnectionWatcher = new QFutureWatcher<bool>(this);
    fetchWatcher = new QFutureWatcher<QList<ImapClient::EmailMessage>>(this);
    
    connect(connectionWatcher, &QFutureWatcher<bool>::finished, 
            this, &EmailProtectionTab::onConnectionFinished);
    connect(testConnectionWatcher, &QFutureWatcher<bool>::finished, 
            this, &EmailProtectionTab::onTestConnectionFinished);
    connect(resetConnectionWatcher, &QFutureWatcher<bool>::finished, 
            this, &EmailProtectionTab::onResetConnectionFinished);
    connect(fetchWatcher, &QFutureWatcher<QList<ImapClient::EmailMessage>>::finished, 
            this, &EmailProtectionTab::onFetchFinished);
    
    setupUI();
}

void EmailProtectionTab::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    
    mainStack = new QStackedWidget(this);
    
    setupVaultPage();
    setupWizardPage1();
    setupWizardPage2();
    setupWizardPage3();
    setupEmailViewPage();
    
    mainStack->addWidget(vaultPage);
    mainStack->addWidget(wizardPage1);
    mainStack->addWidget(wizardPage2);
    mainStack->addWidget(wizardPage3);
    mainStack->addWidget(emailViewPage);
    
    mainLayout->addWidget(mainStack);
    
    checkSavedCredentials();
}

void EmailProtectionTab::setupVaultPage() {
    vaultPage = new QWidget();
    QVBoxLayout *pageLayout = new QVBoxLayout(vaultPage);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    
    QScrollArea *scrollArea = new QScrollArea();
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    
    QWidget *contentWidget = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(contentWidget);
    layout->setAlignment(Qt::AlignCenter);
    layout->setSpacing(20);
    
    QLabel *iconLabel = new QLabel();
    iconLabel->setText("🔒");
    iconLabel->setStyleSheet("font-size: 72px;");
    iconLabel->setAlignment(Qt::AlignCenter);
    
    QLabel *titleLabel = new QLabel("Secure Credential Vault");
    titleLabel->setStyleSheet("font-size: 28px; font-weight: bold; color: #4a90d9;");
    titleLabel->setAlignment(Qt::AlignCenter);
    
    vaultStatusLabel = new QLabel();
    vaultStatusLabel->setStyleSheet("font-size: 14px; color: #888888;");
    vaultStatusLabel->setAlignment(Qt::AlignCenter);
    
    QGroupBox *vaultGroup = new QGroupBox();
    vaultGroup->setStyleSheet(
        "QGroupBox { border: 2px solid #3a3a4a; border-radius: 10px; padding: 20px; background: #2a2a3a; }"
    );
    vaultGroup->setMaximumWidth(400);
    QVBoxLayout *vaultLayout = new QVBoxLayout(vaultGroup);
    
    QLabel *passLabel = new QLabel("Master Password:");
    passLabel->setStyleSheet("font-weight: bold;");
    
    vaultPasswordEdit = new QLineEdit();
    vaultPasswordEdit->setEchoMode(QLineEdit::Password);
    vaultPasswordEdit->setPlaceholderText("Enter your master password");
    vaultPasswordEdit->setStyleSheet("padding: 10px; font-size: 14px;");
    
    unlockVaultBtn = new QPushButton("🔓 Unlock Vault");
    unlockVaultBtn->setStyleSheet(
        "QPushButton { background: #4a90d9; color: white; padding: 12px; "
        "font-size: 14px; font-weight: bold; border-radius: 5px; }"
        "QPushButton:hover { background: #5aa0e9; }"
    );
    connect(unlockVaultBtn, &QPushButton::clicked, this, &EmailProtectionTab::unlockVault);
    
    setupVaultBtn = new QPushButton("🔐 Create New Vault");
    setupVaultBtn->setStyleSheet(
        "QPushButton { background: #27ae60; color: white; padding: 12px; "
        "font-size: 14px; font-weight: bold; border-radius: 5px; }"
        "QPushButton:hover { background: #2ecc71; }"
    );
    connect(setupVaultBtn, &QPushButton::clicked, this, &EmailProtectionTab::setupVault);
    
    QPushButton *forgotPasswordBtn = new QPushButton("Forgot Master Password?");
    forgotPasswordBtn->setStyleSheet(
        "QPushButton { background: transparent; color: #e67e22; padding: 8px; "
        "font-size: 12px; border: none; text-decoration: underline; }"
        "QPushButton:hover { color: #f39c12; }"
    );
    connect(forgotPasswordBtn, &QPushButton::clicked, this, &EmailProtectionTab::forgotMasterPassword);
    
    QPushButton *skipBtn = new QPushButton("Skip (Don't Save Credentials)");
    skipBtn->setStyleSheet(
        "QPushButton { background: transparent; color: #888888; padding: 8px; "
        "font-size: 12px; border: none; }"
        "QPushButton:hover { color: #aaaaaa; }"
    );
    connect(skipBtn, &QPushButton::clicked, [this]() {
        currentWizardStep = 0;
        mainStack->setCurrentIndex(1);
    });
    
    vaultLayout->addWidget(passLabel);
    vaultLayout->addWidget(vaultPasswordEdit);
    vaultLayout->addSpacing(10);
    vaultLayout->addWidget(unlockVaultBtn);
    vaultLayout->addWidget(setupVaultBtn);
    vaultLayout->addWidget(forgotPasswordBtn);
    
    layout->addWidget(iconLabel);
    layout->addWidget(titleLabel);
    layout->addWidget(vaultStatusLabel);
    layout->addWidget(vaultGroup);
    layout->addWidget(skipBtn);
    layout->addStretch();
    
    scrollArea->setWidget(contentWidget);
    pageLayout->addWidget(scrollArea);
}

void EmailProtectionTab::checkSavedCredentials() {
    CredentialVault& vault = CredentialVault::getInstance();
    
    if (vault.isInitialized() && vault.hasStoredCredentials()) {
        vaultStatusLabel->setText("Saved credentials found. Enter your master password to unlock.");
        unlockVaultBtn->setVisible(true);
        setupVaultBtn->setVisible(false);
        mainStack->setCurrentIndex(0);
    } else if (vault.isInitialized()) {
        vaultStatusLabel->setText("Vault exists but no email credentials saved.\nEnter password to unlock or set up new.");
        unlockVaultBtn->setVisible(true);
        setupVaultBtn->setVisible(false);
        mainStack->setCurrentIndex(0);
    } else {
        currentWizardStep = 0;
        mainStack->setCurrentIndex(1);
    }
}

void EmailProtectionTab::unlockVault() {
    QString password = vaultPasswordEdit->text();
    if (password.isEmpty()) {
        QMessageBox::warning(this, "Password Required", "Please enter your master password.");
        return;
    }
    
    CredentialVault& vault = CredentialVault::getInstance();
    if (vault.unlock(password)) {
        vaultPasswordEdit->clear();
        loadSavedCredentials();
    } else {
        QMessageBox::critical(this, "Unlock Failed", "Incorrect master password. Please try again.");
        vaultPasswordEdit->clear();
    }
}

void EmailProtectionTab::setupVault() {
    QString password = vaultPasswordEdit->text();
    if (password.isEmpty()) {
        QMessageBox::warning(this, "Password Required", 
            "Please enter a master password to protect your credentials.");
        return;
    }
    
    if (password.length() < 8) {
        QMessageBox::warning(this, "Weak Password", 
            "Please use a password with at least 8 characters.");
        return;
    }
    
    CredentialVault& vault = CredentialVault::getInstance();
    vault.setMasterPassword(password);
    vaultPasswordEdit->clear();
    
    QMessageBox::information(this, "Vault Created", 
        "Your secure credential vault has been created.\n"
        "Your email credentials will be encrypted and saved after you connect.");
    
    currentWizardStep = 0;
    mainStack->setCurrentIndex(1);
}

void EmailProtectionTab::loadSavedCredentials() {
    CredentialVault& vault = CredentialVault::getInstance();
    
    QString username, password;
    if (vault.getCredential("email_imap", username, password)) {
        QString server, portStr;
        vault.getCredential("email_server", server, server);
        vault.getCredential("email_port", portStr, portStr);
        
        emailAddressEdit->setText(username);
        passwordEdit->setText(password);
        
        bool foundProvider = false;
        for (int i = 0; i < serverCombo->count(); i++) {
            if (serverCombo->itemData(i).toString() == server) {
                serverCombo->setCurrentIndex(i);
                foundProvider = true;
                break;
            }
        }
        
        if (!foundProvider && !server.isEmpty()) {
            serverCombo->setCurrentIndex(serverCombo->count() - 1);
            customServerEdit->setText(server);
            if (!portStr.isEmpty()) {
                customPortEdit->setText(portStr);
            }
        }
        
        password.fill('\0');
        
        currentWizardStep = 1;
        
        QMessageBox::StandardButton reply = QMessageBox::question(this, "Saved Credentials",
            "Found saved credentials for: " + username + "\n\nConnect now?",
            QMessageBox::Yes | QMessageBox::No);
        
        if (reply == QMessageBox::Yes) {
            connectToEmail();
        } else {
            mainStack->setCurrentIndex(2);
        }
    } else {
        currentWizardStep = 0;
        mainStack->setCurrentIndex(1);
    }
}

bool EmailProtectionTab::saveCredentials() {
    CredentialVault& vault = CredentialVault::getInstance();
    
    if (vault.isLocked()) {
        Logger::getInstance().log(Logger::WARNING, "Cannot save credentials - vault is locked");
        return false;
    }
    
    QString server = pendingSettings.server;
    QString portStr = QString::number(pendingSettings.port);
    
    vault.storeCredential("email_imap", pendingSettings.email, pendingSettings.password);
    vault.storeCredential("email_server", server, server);
    vault.storeCredential("email_port", portStr, portStr);
    
    Logger::getInstance().log(Logger::SUCCESS, "Email credentials saved to vault");
    return true;
}

void EmailProtectionTab::forgetCredentials() {
    CredentialVault& vault = CredentialVault::getInstance();
    vault.deleteCredential("email_imap");
    vault.deleteCredential("email_server");
    vault.deleteCredential("email_port");
    
    QMessageBox::information(this, "Credentials Removed", 
        "Your saved email credentials have been removed from the vault.");
    
    Logger::getInstance().log(Logger::INFO, "Email credentials removed from vault");
}

void EmailProtectionTab::forgotMasterPassword() {
    QDialog dialog(this);
    dialog.setWindowTitle("Reset Master Password");
    dialog.setMinimumWidth(400);
    
    QVBoxLayout *layout = new QVBoxLayout(&dialog);
    
    QLabel *infoLabel = new QLabel(
        "To reset your master password, enter your email credentials.\n"
        "We'll verify them by connecting to your email server.\n\n"
        "After verification, you can set a new master password."
    );
    infoLabel->setWordWrap(true);
    infoLabel->setStyleSheet("color: #888888; margin-bottom: 10px;");
    
    QLabel *emailLabel = new QLabel("Email Address:");
    QLineEdit *emailEdit = new QLineEdit();
    emailEdit->setPlaceholderText("your.email@example.com");
    
    QLabel *passLabel = new QLabel("Email Password (App Password):");
    QLineEdit *passEdit = new QLineEdit();
    passEdit->setEchoMode(QLineEdit::Password);
    passEdit->setPlaceholderText("Enter your email password");
    
    QLabel *providerLabel = new QLabel("Email Provider:");
    QComboBox *providerCombo = new QComboBox();
    providerCombo->addItem("Gmail", "imap.gmail.com");
    providerCombo->addItem("Outlook / Hotmail", "imap-mail.outlook.com");
    providerCombo->addItem("Yahoo Mail", "imap.mail.yahoo.com");
    providerCombo->addItem("iCloud Mail", "imap.mail.me.com");
    
    QHBoxLayout *btnLayout = new QHBoxLayout();
    QPushButton *cancelBtn = new QPushButton("Cancel");
    QPushButton *verifyBtn = new QPushButton("Verify & Reset");
    verifyBtn->setStyleSheet(
        "QPushButton { background: #e67e22; color: white; padding: 10px 20px; font-weight: bold; }"
    );
    btnLayout->addWidget(cancelBtn);
    btnLayout->addWidget(verifyBtn);
    
    layout->addWidget(infoLabel);
    layout->addWidget(emailLabel);
    layout->addWidget(emailEdit);
    layout->addWidget(passLabel);
    layout->addWidget(passEdit);
    layout->addWidget(providerLabel);
    layout->addWidget(providerCombo);
    layout->addSpacing(20);
    layout->addLayout(btnLayout);
    
    connect(cancelBtn, &QPushButton::clicked, &dialog, &QDialog::reject);
    connect(verifyBtn, &QPushButton::clicked, [&]() {
        if (emailEdit->text().isEmpty() || passEdit->text().isEmpty()) {
            QMessageBox::warning(&dialog, "Missing Information", 
                "Please enter both your email address and password.");
            return;
        }
        dialog.accept();
    });
    
    if (dialog.exec() != QDialog::Accepted) {
        return;
    }
    
    QString email = emailEdit->text();
    QString password = passEdit->text();
    QString server = providerCombo->currentData().toString();
    
    bool ok;
    QString newMasterPassword = QInputDialog::getText(this, "New Master Password",
        "Enter a new master password (at least 8 characters):",
        QLineEdit::Password, "", &ok);
    
    if (!ok || newMasterPassword.isEmpty()) {
        return;
    }
    
    if (newMasterPassword.length() < 8) {
        QMessageBox::warning(this, "Weak Password", 
            "Please use a password with at least 8 characters.");
        return;
    }
    
    QString confirmPassword = QInputDialog::getText(this, "Confirm Password",
        "Confirm your new master password:",
        QLineEdit::Password, "", &ok);
    
    if (!ok || confirmPassword != newMasterPassword) {
        QMessageBox::warning(this, "Password Mismatch", 
            "The passwords do not match. Please try again.");
        return;
    }
    
    pendingNewMasterPassword = newMasterPassword;
    
    resetPendingSettings.server = server;
    resetPendingSettings.port = 993;
    resetPendingSettings.email = email;
    resetPendingSettings.password = password;
    resetPendingSettings.useSSL = true;
    
    QMessageBox::information(this, "Verifying...", 
        "Connecting to your email server to verify credentials.\nThis may take a moment.");
    
    QFuture<bool> future = QtConcurrent::run([this]() {
        ImapClient& client = ImapClient::getInstance();
        bool connected = client.connect(resetPendingSettings);
        if (connected) {
            client.disconnect();
        }
        return connected;
    });
    
    resetConnectionWatcher->setFuture(future);
}

void EmailProtectionTab::onResetConnectionFinished() {
    bool success = resetConnectionWatcher->result();
    
    if (success) {
        CredentialVault& vault = CredentialVault::getInstance();
        vault.reset();
        
        vault.setMasterPassword(pendingNewMasterPassword);
        
        vault.storeCredential("email_imap", resetPendingSettings.email, resetPendingSettings.password);
        vault.storeCredential("email_server", resetPendingSettings.server, resetPendingSettings.server);
        vault.storeCredential("email_port", QString::number(resetPendingSettings.port), 
                             QString::number(resetPendingSettings.port));
        
        pendingNewMasterPassword.fill('\0');
        pendingNewMasterPassword.clear();
        resetPendingSettings.password.fill('\0');
        
        QMessageBox::information(this, "Password Reset Successful", 
            "Your master password has been reset and your email credentials have been saved.\n\n"
            "You can now use your new master password to unlock the vault.");
        
        Logger::getInstance().log(Logger::SUCCESS, "Master password reset via email verification");
        
        emailAddressEdit->setText(resetPendingSettings.email);
        serverCombo->setCurrentIndex(0);
        for (int i = 0; i < serverCombo->count(); i++) {
            if (serverCombo->itemData(i).toString() == resetPendingSettings.server) {
                serverCombo->setCurrentIndex(i);
                break;
            }
        }
        
        currentWizardStep = 1;
        mainStack->setCurrentIndex(2);
        
    } else {
        pendingNewMasterPassword.fill('\0');
        pendingNewMasterPassword.clear();
        resetPendingSettings.password.fill('\0');
        
        QMessageBox::critical(this, "Verification Failed", 
            "Could not connect to your email server with those credentials.\n\n"
            "Please check your email address, password, and email provider selection.\n"
            "Make sure you're using an App Password if required.");
        
        Logger::getInstance().log(Logger::ERROR_LEVEL, "Master password reset failed - email verification failed");
    }
}

void EmailProtectionTab::setupWizardPage1() {
    wizardPage1 = new QWidget();
    QVBoxLayout *pageLayout = new QVBoxLayout(wizardPage1);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    
    QScrollArea *scrollArea = new QScrollArea();
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    
    QWidget *contentWidget = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(contentWidget);
    layout->setAlignment(Qt::AlignCenter);
    layout->setSpacing(20);
    
    QLabel *iconLabel = new QLabel();
    iconLabel->setText("📧");
    iconLabel->setStyleSheet("font-size: 72px;");
    iconLabel->setAlignment(Qt::AlignCenter);
    
    QLabel *titleLabel = new QLabel("Email Protection Setup");
    titleLabel->setStyleSheet(
        "font-size: 28px; font-weight: bold; color: #4a90d9;"
    );
    titleLabel->setAlignment(Qt::AlignCenter);
    
    QLabel *subtitleLabel = new QLabel(
        "Connect your email account to scan for phishing attempts,\n"
        "suspicious links, and security threats."
    );
    subtitleLabel->setStyleSheet("font-size: 14px; color: #888888;");
    subtitleLabel->setAlignment(Qt::AlignCenter);
    
    QLabel *stepLabel = new QLabel("Step 1 of 3: Choose Your Email Provider");
    stepLabel->setStyleSheet("font-size: 16px; font-weight: bold; margin-top: 30px;");
    stepLabel->setAlignment(Qt::AlignCenter);
    
    QGroupBox *providerGroup = new QGroupBox();
    providerGroup->setStyleSheet(
        "QGroupBox { border: 2px solid #3a3a4a; border-radius: 10px; padding: 20px; background: #2a2a3a; }"
    );
    QVBoxLayout *providerLayout = new QVBoxLayout(providerGroup);
    
    serverCombo = new QComboBox();
    serverCombo->setStyleSheet(
        "QComboBox { padding: 10px; font-size: 14px; border-radius: 5px; }"
    );
    serverCombo->addItem("📨 Gmail (Recommended)", "imap.gmail.com");
    serverCombo->addItem("📧 Outlook / Hotmail", "imap-mail.outlook.com");
    serverCombo->addItem("📬 Yahoo Mail", "imap.mail.yahoo.com");
    serverCombo->addItem("📮 iCloud Mail", "imap.mail.me.com");
    serverCombo->addItem("⚙️ Custom IMAP Server", "custom");
    connect(serverCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), 
            this, &EmailProtectionTab::onProviderSelected);
    
    customServerEdit = new QLineEdit();
    customServerEdit->setPlaceholderText("Custom IMAP server (e.g., mail.example.com)");
    customServerEdit->setVisible(false);
    
    customPortEdit = new QLineEdit();
    customPortEdit->setPlaceholderText("Port (default: 993)");
    customPortEdit->setVisible(false);
    
    providerLayout->addWidget(new QLabel("Select your email provider:"));
    providerLayout->addWidget(serverCombo);
    providerLayout->addWidget(customServerEdit);
    providerLayout->addWidget(customPortEdit);
    
    QHBoxLayout *btnLayout = new QHBoxLayout();
    btnLayout->addStretch();
    
    nextBtn = new QPushButton("Next →");
    nextBtn->setStyleSheet(
        "QPushButton { background: #4a90d9; color: white; padding: 12px 30px; "
        "font-size: 14px; font-weight: bold; border-radius: 5px; }"
        "QPushButton:hover { background: #5aa0e9; }"
    );
    connect(nextBtn, &QPushButton::clicked, this, &EmailProtectionTab::nextWizardStep);
    
    btnLayout->addWidget(nextBtn);
    btnLayout->addStretch();
    
    layout->addWidget(iconLabel);
    layout->addWidget(titleLabel);
    layout->addWidget(subtitleLabel);
    layout->addWidget(stepLabel);
    layout->addWidget(providerGroup);
    layout->addLayout(btnLayout);
    layout->addStretch();
    
    scrollArea->setWidget(contentWidget);
    pageLayout->addWidget(scrollArea);
}

void EmailProtectionTab::setupWizardPage2() {
    wizardPage2 = new QWidget();
    QVBoxLayout *pageLayout = new QVBoxLayout(wizardPage2);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    
    QScrollArea *scrollArea = new QScrollArea();
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    
    QWidget *contentWidget = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(contentWidget);
    layout->setAlignment(Qt::AlignCenter);
    layout->setSpacing(20);
    
    QLabel *iconLabel = new QLabel();
    iconLabel->setText("🔐");
    iconLabel->setStyleSheet("font-size: 72px;");
    iconLabel->setAlignment(Qt::AlignCenter);
    
    QLabel *titleLabel = new QLabel("Enter Your Credentials");
    titleLabel->setStyleSheet("font-size: 28px; font-weight: bold; color: #4a90d9;");
    titleLabel->setAlignment(Qt::AlignCenter);
    
    QLabel *stepLabel = new QLabel("Step 2 of 3: Account Details");
    stepLabel->setStyleSheet("font-size: 16px; font-weight: bold;");
    stepLabel->setAlignment(Qt::AlignCenter);
    
    QGroupBox *credGroup = new QGroupBox();
    credGroup->setStyleSheet(
        "QGroupBox { border: 2px solid #3a3a4a; border-radius: 10px; padding: 20px; background: #2a2a3a; }"
    );
    credGroup->setMaximumWidth(500);
    QVBoxLayout *credLayout = new QVBoxLayout(credGroup);
    
    QLabel *emailLabel = new QLabel("Email Address:");
    emailLabel->setStyleSheet("font-weight: bold;");
    emailAddressEdit = new QLineEdit();
    emailAddressEdit->setPlaceholderText("your.email@gmail.com");
    emailAddressEdit->setStyleSheet("padding: 10px; font-size: 14px;");
    
    QLabel *passLabel = new QLabel("App Password:");
    passLabel->setStyleSheet("font-weight: bold;");
    passwordEdit = new QLineEdit();
    passwordEdit->setEchoMode(QLineEdit::Password);
    passwordEdit->setPlaceholderText("Enter app-specific password");
    passwordEdit->setStyleSheet("padding: 10px; font-size: 14px;");
    
    QLabel *infoLabel = new QLabel(
        "ℹ️ For Gmail, Outlook, and Yahoo, you need to use an App Password.\n"
        "This is a special password created in your account security settings."
    );
    infoLabel->setStyleSheet("color: #f39c12; font-size: 12px; padding: 10px;");
    infoLabel->setWordWrap(true);
    
    rememberCredentialsCheck = new QCheckBox("Remember my credentials (encrypted)");
    rememberCredentialsCheck->setStyleSheet("color: #4a90d9; font-size: 12px;");
    rememberCredentialsCheck->setChecked(true);
    
    credLayout->addWidget(emailLabel);
    credLayout->addWidget(emailAddressEdit);
    credLayout->addSpacing(10);
    credLayout->addWidget(passLabel);
    credLayout->addWidget(passwordEdit);
    credLayout->addWidget(infoLabel);
    credLayout->addWidget(rememberCredentialsCheck);
    
    QHBoxLayout *btnLayout = new QHBoxLayout();
    
    prevBtn = new QPushButton("← Back");
    prevBtn->setStyleSheet(
        "QPushButton { background: #555555; color: white; padding: 12px 30px; "
        "font-size: 14px; border-radius: 5px; }"
        "QPushButton:hover { background: #666666; }"
    );
    connect(prevBtn, &QPushButton::clicked, this, &EmailProtectionTab::prevWizardStep);
    
    testConnectionBtn = new QPushButton("🔌 Test Connection");
    testConnectionBtn->setStyleSheet(
        "QPushButton { background: #3498db; color: white; padding: 12px 20px; "
        "font-size: 14px; border-radius: 5px; }"
        "QPushButton:hover { background: #5dade2; }"
    );
    connect(testConnectionBtn, &QPushButton::clicked, this, &EmailProtectionTab::testConnection);
    
    connectBtn = new QPushButton("Connect & Save →");
    connectBtn->setStyleSheet(
        "QPushButton { background: #27ae60; color: white; padding: 12px 30px; "
        "font-size: 14px; font-weight: bold; border-radius: 5px; }"
        "QPushButton:hover { background: #2ecc71; }"
    );
    connect(connectBtn, &QPushButton::clicked, this, &EmailProtectionTab::connectToEmail);
    
    btnLayout->addWidget(prevBtn);
    btnLayout->addStretch();
    btnLayout->addWidget(testConnectionBtn);
    btnLayout->addWidget(connectBtn);
    
    layout->addWidget(iconLabel);
    layout->addWidget(titleLabel);
    layout->addWidget(stepLabel);
    layout->addWidget(credGroup);
    layout->addLayout(btnLayout);
    layout->addStretch();
    
    scrollArea->setWidget(contentWidget);
    pageLayout->addWidget(scrollArea);
}

void EmailProtectionTab::setupWizardPage3() {
    wizardPage3 = new QWidget();
    QVBoxLayout *pageLayout = new QVBoxLayout(wizardPage3);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    
    QScrollArea *scrollArea = new QScrollArea();
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    
    QWidget *contentWidget = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(contentWidget);
    layout->setAlignment(Qt::AlignCenter);
    layout->setSpacing(20);
    
    QLabel *iconLabel = new QLabel();
    iconLabel->setText("⏳");
    iconLabel->setStyleSheet("font-size: 72px;");
    iconLabel->setAlignment(Qt::AlignCenter);
    
    QLabel *titleLabel = new QLabel("Connecting...");
    titleLabel->setStyleSheet("font-size: 28px; font-weight: bold; color: #4a90d9;");
    titleLabel->setAlignment(Qt::AlignCenter);
    
    connectionProgress = new QProgressBar();
    connectionProgress->setRange(0, 0);
    connectionProgress->setMaximumWidth(400);
    connectionProgress->setStyleSheet(
        "QProgressBar { border: 2px solid #3a3a4a; border-radius: 5px; height: 25px; }"
        "QProgressBar::chunk { background: #4a90d9; }"
    );
    
    connectionStatusLabel = new QLabel("Establishing secure connection...");
    connectionStatusLabel->setStyleSheet("font-size: 14px; color: #888888;");
    connectionStatusLabel->setAlignment(Qt::AlignCenter);
    
    layout->addWidget(iconLabel);
    layout->addWidget(titleLabel);
    layout->addWidget(connectionProgress);
    layout->addWidget(connectionStatusLabel);
    layout->addStretch();
    
    scrollArea->setWidget(contentWidget);
    pageLayout->addWidget(scrollArea);
}

void EmailProtectionTab::setupEmailViewPage() {
    emailViewPage = new QWidget();
    QVBoxLayout *pageLayout = new QVBoxLayout(emailViewPage);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    
    QScrollArea *scrollArea = new QScrollArea();
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    
    QWidget *contentWidget = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(contentWidget);
    
    QHBoxLayout *headerLayout = new QHBoxLayout();
    
    QLabel *titleLabel = new QLabel("📧 Email Protection - Connected");
    titleLabel->setStyleSheet("font-size: 20px; font-weight: bold; color: #2ecc71;");
    
    QPushButton *refreshBtn = new QPushButton("🔄 Refresh");
    refreshBtn->setStyleSheet(
        "QPushButton { background: #4a90d9; color: white; padding: 8px 15px; border-radius: 5px; }"
    );
    connect(refreshBtn, &QPushButton::clicked, this, &EmailProtectionTab::refreshEmails);
    
    disconnectBtn = new QPushButton("Disconnect");
    disconnectBtn->setStyleSheet(
        "QPushButton { background: #e74c3c; color: white; padding: 8px 15px; border-radius: 5px; }"
    );
    connect(disconnectBtn, &QPushButton::clicked, this, &EmailProtectionTab::disconnectEmail);
    
    QPushButton *forgetBtn = new QPushButton("🗑️ Forget Saved");
    forgetBtn->setStyleSheet(
        "QPushButton { background: #95a5a6; color: white; padding: 8px 15px; border-radius: 5px; }"
        "QPushButton:hover { background: #7f8c8d; }"
    );
    connect(forgetBtn, &QPushButton::clicked, this, &EmailProtectionTab::forgetCredentials);
    
    headerLayout->addWidget(titleLabel);
    headerLayout->addStretch();
    headerLayout->addWidget(refreshBtn);
    headerLayout->addWidget(forgetBtn);
    headerLayout->addWidget(disconnectBtn);
    
    QSplitter *splitter = new QSplitter(Qt::Horizontal);
    
    QWidget *listWidget = new QWidget();
    QVBoxLayout *listLayout = new QVBoxLayout(listWidget);
    listLayout->setContentsMargins(0, 0, 0, 0);
    
    QLabel *inboxLabel = new QLabel("📥 Inbox");
    inboxLabel->setStyleSheet("font-weight: bold; font-size: 14px;");
    
    emailList = new QListWidget();
    emailList->setStyleSheet(
        "QListWidget { border: 1px solid #3a3a4a; border-radius: 5px; }"
        "QListWidget::item { padding: 10px; border-bottom: 1px solid #3a3a4a; }"
        "QListWidget::item:selected { background: #4a90d9; }"
    );
    connect(emailList, &QListWidget::currentRowChanged, this, &EmailProtectionTab::analyzeSelectedEmail);
    
    listLayout->addWidget(inboxLabel);
    listLayout->addWidget(emailList);
    
    QWidget *detailWidget = new QWidget();
    QVBoxLayout *detailLayout = new QVBoxLayout(detailWidget);
    
    spamScoreLabel = new QLabel("Select an email to analyze");
    spamScoreLabel->setStyleSheet(
        "font-weight: bold; font-size: 16px; padding: 10px; "
        "background: #2a2a3a; border-radius: 5px;"
    );
    
    QLabel *contentLabel = new QLabel("📄 Email Content:");
    contentLabel->setStyleSheet("font-weight: bold;");
    
    emailContentText = new QTextEdit();
    emailContentText->setReadOnly(true);
    emailContentText->setStyleSheet("border: 1px solid #3a3a4a; border-radius: 5px;");
    
    QLabel *analysisLabel = new QLabel("🔍 Security Analysis:");
    analysisLabel->setStyleSheet("font-weight: bold;");
    
    analysisText = new QTextEdit();
    analysisText->setReadOnly(true);
    analysisText->setMaximumHeight(150);
    analysisText->setStyleSheet("border: 1px solid #3a3a4a; border-radius: 5px;");
    
    detailLayout->addWidget(spamScoreLabel);
    detailLayout->addWidget(contentLabel);
    detailLayout->addWidget(emailContentText, 1);
    detailLayout->addWidget(analysisLabel);
    detailLayout->addWidget(analysisText);
    
    splitter->addWidget(listWidget);
    splitter->addWidget(detailWidget);
    splitter->setSizes({300, 600});
    
    layout->addLayout(headerLayout);
    layout->addWidget(splitter);
    
    scrollArea->setWidget(contentWidget);
    pageLayout->addWidget(scrollArea);
}

void EmailProtectionTab::onProviderSelected(int index) {
    bool isCustom = serverCombo->itemData(index).toString() == "custom";
    customServerEdit->setVisible(isCustom);
    customPortEdit->setVisible(isCustom);
}

void EmailProtectionTab::nextWizardStep() {
    currentWizardStep++;
    mainStack->setCurrentIndex(currentWizardStep + 1);
}

void EmailProtectionTab::prevWizardStep() {
    if (currentWizardStep > 0) {
        currentWizardStep--;
        mainStack->setCurrentIndex(currentWizardStep + 1);
    }
}

void EmailProtectionTab::testConnection() {
    QString email = emailAddressEdit->text().trimmed();
    QString password = passwordEdit->text();
    
    if (email.isEmpty() || password.isEmpty()) {
        QMessageBox::warning(this, "Input Required", 
            "Please enter your email address and app password to test the connection.");
        return;
    }
    
    mainStack->setCurrentIndex(3);
    connectionStatusLabel->setText("Testing connection (credentials will not be saved)...");
    
    ImapClient::ConnectionSettings settings;
    QString selectedServer = serverCombo->currentData().toString();
    if (selectedServer == "custom") {
        settings.server = customServerEdit->text().trimmed();
        settings.port = customPortEdit->text().toInt();
        if (settings.port == 0) settings.port = 993;
    } else {
        settings.server = selectedServer;
        settings.port = 993;
    }
    
    settings.email = email;
    settings.password = password;
    settings.useSSL = true;
    
    connectionStatusLabel->setText("Testing connection to " + settings.server + "...");
    
    QFuture<bool> future = QtConcurrent::run([settings]() {
        ImapClient& client = ImapClient::getInstance();
        bool result = client.connect(settings);
        if (result) {
            client.disconnect();
        }
        return result;
    });
    
    testConnectionWatcher->setFuture(future);
}

void EmailProtectionTab::onTestConnectionFinished() {
    bool success = testConnectionWatcher->result();
    
    if (success) {
        QMessageBox::StandardButton reply = QMessageBox::information(this, "Connection Successful",
            "Connection test passed! Your credentials are valid.\n\n"
            "Would you like to connect and save your credentials now?",
            QMessageBox::Yes | QMessageBox::No);
        
        if (reply == QMessageBox::Yes) {
            mainStack->setCurrentIndex(2);
            connectToEmail();
        } else {
            mainStack->setCurrentIndex(2);
        }
    } else {
        QMessageBox::critical(this, "Connection Failed", 
            "Connection test failed.\n\n" + ImapClient::getInstance().getLastError() +
            "\n\nPlease check your credentials and try again.");
        mainStack->setCurrentIndex(2);
    }
}

void EmailProtectionTab::connectToEmail() {
    QString email = emailAddressEdit->text().trimmed();
    QString password = passwordEdit->text();
    
    if (email.isEmpty() || password.isEmpty()) {
        QMessageBox::warning(this, "Input Required", 
            "Please enter your email address and app password.");
        return;
    }
    
    mainStack->setCurrentIndex(3);
    connectionStatusLabel->setText("Establishing secure connection...");
    
    ImapClient::ConnectionSettings settings;
    QString selectedServer = serverCombo->currentData().toString();
    if (selectedServer == "custom") {
        settings.server = customServerEdit->text().trimmed();
        settings.port = customPortEdit->text().toInt();
        if (settings.port == 0) settings.port = 993;
    } else {
        settings.server = selectedServer;
        settings.port = 993;
    }
    
    settings.email = email;
    settings.password = password;
    settings.useSSL = true;
    
    pendingSettings = settings;
    
    connectionStatusLabel->setText("Authenticating with " + settings.server + "...");
    
    QFuture<bool> future = QtConcurrent::run([settings]() {
        ImapClient& client = ImapClient::getInstance();
        return client.connect(settings);
    });
    
    connectionWatcher->setFuture(future);
}

void EmailProtectionTab::onConnectionFinished() {
    bool success = connectionWatcher->result();
    
    if (success) {
        bool savedSuccessfully = false;
        if (rememberCredentialsCheck->isChecked()) {
            savedSuccessfully = saveCredentials();
            if (!savedSuccessfully) {
                QMessageBox::warning(this, "Credentials Not Saved",
                    "Connection successful, but credentials could not be saved.\n"
                    "The vault may be locked. You can set up the vault from the Email Protection tab next time.");
            }
        }
        
        passwordEdit->clear();
        pendingSettings.password.fill('\0');
        pendingSettings.password.clear();
        
        connectionStatusLabel->setText("Fetching emails...");
        
        QFuture<QList<ImapClient::EmailMessage>> future = QtConcurrent::run([]() {
            return ImapClient::getInstance().fetchEmails(20);
        });
        
        fetchWatcher->setFuture(future);
    } else {
        pendingSettings.password.fill('\0');
        pendingSettings.password.clear();
        
        QMessageBox::critical(this, "Connection Failed", 
            "Could not connect to email server.\n\n" + ImapClient::getInstance().getLastError());
        mainStack->setCurrentIndex(2);
    }
}

void EmailProtectionTab::onFetchFinished() {
    fetchedEmails = fetchWatcher->result();
    populateEmailList();
    mainStack->setCurrentIndex(4);
    
    if (fetchedEmails.isEmpty()) {
        Logger::getInstance().log(Logger::WARNING, "Connected but no emails fetched - inbox may be empty or fetch failed");
    } else {
        Logger::getInstance().log(Logger::SUCCESS, QString("Connected and fetched %1 emails").arg(fetchedEmails.size()));
    }
}

void EmailProtectionTab::disconnectEmail() {
    ImapClient::getInstance().disconnect();
    emailList->clear();
    emailContentText->clear();
    analysisText->clear();
    spamScoreLabel->setText("Select an email to analyze");
    fetchedEmails.clear();
    currentWizardStep = 0;
    mainStack->setCurrentIndex(1);
    
    Logger::getInstance().log(Logger::INFO, "Disconnected from email");
}

void EmailProtectionTab::refreshEmails() {
    if (!ImapClient::getInstance().isConnected()) {
        QMessageBox::warning(this, "Not Connected", 
            "Please connect to your email first.");
        return;
    }
    
    connectionStatusLabel->setText("Refreshing emails...");
    mainStack->setCurrentIndex(3);
    
    QFuture<QList<ImapClient::EmailMessage>> future = QtConcurrent::run([]() {
        return ImapClient::getInstance().fetchEmails(20);
    });
    
    fetchWatcher->setFuture(future);
}

void EmailProtectionTab::populateEmailList() {
    emailList->clear();
    
    for (const ImapClient::EmailMessage& msg : fetchedEmails) {
        QString displayText = QString("%1\n%2").arg(msg.subject, msg.from);
        QListWidgetItem *item = new QListWidgetItem(displayText);
        item->setData(Qt::UserRole, msg.id);
        emailList->addItem(item);
    }
    
    if (fetchedEmails.isEmpty()) {
        emailList->addItem("No emails found or unable to fetch emails.");
    }
}

void EmailProtectionTab::analyzeSelectedEmail() {
    int row = emailList->currentRow();
    if (row < 0 || row >= fetchedEmails.size()) return;
    
    const ImapClient::EmailMessage& email = fetchedEmails[row];
    
    QString content = QString(
        "From: %1\n"
        "To: %2\n"
        "Date: %3\n"
        "Subject: %4\n"
        "─────────────────────────────────\n\n"
        "%5"
    ).arg(email.from, email.to, email.date, email.subject, email.body);
    
    emailContentText->setText(content);
    
    ImapClient& client = ImapClient::getInstance();
    ImapClient::AnalysisResult analysis = client.analyzeEmail(email);
    
    QString scoreColor;
    QString riskEmoji;
    if (analysis.riskLevel == "High") {
        scoreColor = "#e74c3c";
        riskEmoji = "🔴";
    } else if (analysis.riskLevel == "Medium") {
        scoreColor = "#f39c12";
        riskEmoji = "🟡";
    } else {
        scoreColor = "#2ecc71";
        riskEmoji = "🟢";
    }
    
    spamScoreLabel->setText(QString("%1 Spam Score: %2% (%3 Risk)")
                             .arg(riskEmoji)
                             .arg(analysis.spamScore)
                             .arg(analysis.riskLevel));
    spamScoreLabel->setStyleSheet(QString(
        "color: %1; font-weight: bold; font-size: 16px; padding: 10px; "
        "background: #2a2a3a; border-radius: 5px;"
    ).arg(scoreColor));
    
    QString analysisContent = "Security Analysis Results:\n\n";
    
    analysisContent += QString("• Sender Verification: %1\n")
                        .arg(analysis.senderVerified ? "✅ PASSED" : "⚠️ UNVERIFIED");
    analysisContent += QString("• Suspicious Links: %1\n")
                        .arg(analysis.hasSuspiciousLinks ? "⚠️ DETECTED" : "✅ None found");
    analysisContent += QString("• Phishing Indicators: %1\n")
                        .arg(analysis.hasPhishingIndicators ? "⚠️ DETECTED" : "✅ None found");
    analysisContent += QString("• Attachments: %1\n\n")
                        .arg(email.hasAttachments ? "📎 Present" : "None");
    
    if (!analysis.warnings.isEmpty()) {
        analysisContent += "Warnings:\n";
        for (const QString& warning : analysis.warnings) {
            analysisContent += QString("  • %1\n").arg(warning);
        }
    }
    
    analysisText->setText(analysisContent);
    analysisText->setStyleSheet(QString("color: %1; border: 1px solid #3a3a4a; border-radius: 5px;")
                                  .arg(scoreColor));
}
