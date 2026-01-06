#ifndef SSLANALYZER_H
#define SSLANALYZER_H

#include <QString>
#include <QDateTime>
#include <QSslCertificate>

class SslAnalyzer {
public:
    struct SslResult {
        QString domain;
        bool hasValidCert;
        QString issuer;
        QString subject;
        QDateTime validFrom;
        QDateTime validUntil;
        int daysUntilExpiry;
        QStringList warnings;
        bool success;
        QString errorMessage;
    };
    
    static SslAnalyzer& getInstance() {
        static SslAnalyzer instance;
        return instance;
    }
    
    SslResult analyze(const QString& domain);
    bool isCertificateValid(const SslResult& result);
    
private:
    SslAnalyzer() = default;
    ~SslAnalyzer() = default;
    SslAnalyzer(const SslAnalyzer&) = delete;
    SslAnalyzer& operator=(const SslAnalyzer&) = delete;
};

#endif
