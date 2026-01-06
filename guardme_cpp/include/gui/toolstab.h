#ifndef TOOLSTAB_H
#define TOOLSTAB_H

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QListWidget>
#include <QLabel>
#include <QProgressBar>
#include <QClipboard>
#include <QApplication>

class ToolsTab : public QWidget {
    Q_OBJECT

public:
    explicit ToolsTab(QWidget *parent = nullptr);

private slots:
    void analyzeUrl();
    void checkEmailBreach();
    void checkPasswordBreach();
    void addToWhitelist();
    void removeFromWhitelist();
    void startVirusScan();
    void performWhoisLookup();
    void generatePassword();
    void copyPasswordToClipboard();

private:
    void setupUI();
    void loadWhitelist();
    
    QLineEdit *urlInput;
    QTextEdit *urlResultsText;
    QLabel *urlThreatLabel;
    
    QLineEdit *emailInput;
    QTextEdit *emailResultsText;
    
    QLineEdit *passwordInput;
    QLabel *passwordResultLabel;
    
    QLineEdit *whitelistInput;
    QListWidget *whitelistList;
    
    QLineEdit *scanPathInput;
    QTextEdit *scanResultsText;
    QProgressBar *scanProgress;
    
    QLineEdit *whoisInput;
    QTextEdit *whoisResultsText;
    
    QLineEdit *generatedPasswordDisplay;
};

#endif
