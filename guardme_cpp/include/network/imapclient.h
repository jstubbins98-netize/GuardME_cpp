#ifndef IMAPCLIENT_H
#define IMAPCLIENT_H

#include <QString>
#include <QStringList>
#include <QList>
#include <QDateTime>

class ImapClient {
public:
    struct EmailMessage {
        int id;
        QString from;
        QString to;
        QString subject;
        QString date;
        QString body;
        QStringList attachments;
        bool hasAttachments;
    };
    
    struct ConnectionSettings {
        QString server;
        int port;
        QString email;
        QString password;
        bool useSSL;
    };
    
    struct AnalysisResult {
        int spamScore;
        QString riskLevel;
        QStringList warnings;
        bool hasSuspiciousLinks;
        bool hasPhishingIndicators;
        bool senderVerified;
    };
    
    static ImapClient& getInstance() {
        static ImapClient instance;
        return instance;
    }
    
    bool connect(const ConnectionSettings& settings);
    void disconnect();
    bool isConnected() const { return connected; }
    
    QList<EmailMessage> fetchEmails(int count = 10);
    EmailMessage fetchEmailById(int id);
    
    AnalysisResult analyzeEmail(const EmailMessage& email);
    
    QString getLastError() const { return lastError; }
    
private:
    ImapClient();
    ~ImapClient();
    ImapClient(const ImapClient&) = delete;
    ImapClient& operator=(const ImapClient&) = delete;
    
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp);
    
    QString extractHeader(const QString& raw, const QString& headerName);
    QString extractBody(const QString& raw);
    QStringList extractLinks(const QString& text);
    bool isSuspiciousLink(const QString& url);
    bool hasPhishingKeywords(const QString& text);
    
    bool connected;
    ConnectionSettings currentSettings;
    QString lastError;
    QString sessionData;
};

#endif
