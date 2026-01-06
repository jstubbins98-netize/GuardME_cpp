#ifndef EMAILPROTECTIONTAB_H
#define EMAILPROTECTIONTAB_H

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QListWidget>
#include <QLabel>
#include <QComboBox>
#include <QStackedWidget>
#include <QProgressBar>
#include <QFutureWatcher>
#include <QCheckBox>
#include "network/imapclient.h"

class EmailProtectionTab : public QWidget {
    Q_OBJECT

public:
    explicit EmailProtectionTab(QWidget *parent = nullptr);

private slots:
    void connectToEmail();
    void testConnection();
    void disconnectEmail();
    void refreshEmails();
    void analyzeSelectedEmail();
    void onProviderSelected(int index);
    void nextWizardStep();
    void prevWizardStep();
    void onConnectionFinished();
    void onTestConnectionFinished();
    void onFetchFinished();
    void unlockVault();
    void setupVault();
    void forgetCredentials();
    void forgotMasterPassword();
    void onResetConnectionFinished();

private:
    void setupUI();
    void setupVaultPage();
    void setupWizardPage1();
    void setupWizardPage2();
    void setupWizardPage3();
    void setupEmailViewPage();
    void updateWizardButtons();
    void showConnectionResult(bool success, const QString& message);
    void populateEmailList();
    void checkSavedCredentials();
    bool saveCredentials();
    void loadSavedCredentials();
    
    QStackedWidget *mainStack;
    
    QWidget *vaultPage;
    QWidget *wizardPage1;
    QWidget *wizardPage2;
    QWidget *wizardPage3;
    QWidget *emailViewPage;
    
    QLineEdit *vaultPasswordEdit;
    QPushButton *unlockVaultBtn;
    QPushButton *setupVaultBtn;
    QLabel *vaultStatusLabel;
    QCheckBox *rememberCredentialsCheck;
    
    QLabel *wizardTitleLabel;
    QLabel *wizardStepLabel;
    QLabel *wizardIconLabel;
    
    QComboBox *serverCombo;
    QLineEdit *customServerEdit;
    QLineEdit *customPortEdit;
    QLineEdit *emailAddressEdit;
    QLineEdit *passwordEdit;
    
    QPushButton *nextBtn;
    QPushButton *prevBtn;
    QPushButton *connectBtn;
    QPushButton *testConnectionBtn;
    QPushButton *disconnectBtn;
    
    QProgressBar *connectionProgress;
    QLabel *connectionStatusLabel;
    
    QListWidget *emailList;
    QTextEdit *emailContentText;
    QLabel *spamScoreLabel;
    QTextEdit *analysisText;
    
    int currentWizardStep;
    QList<ImapClient::EmailMessage> fetchedEmails;
    
    QFutureWatcher<bool> *connectionWatcher;
    QFutureWatcher<bool> *testConnectionWatcher;
    QFutureWatcher<bool> *resetConnectionWatcher;
    QFutureWatcher<QList<ImapClient::EmailMessage>> *fetchWatcher;
    ImapClient::ConnectionSettings pendingSettings;
    ImapClient::ConnectionSettings resetPendingSettings;
    QString pendingNewMasterPassword;
};

#endif
