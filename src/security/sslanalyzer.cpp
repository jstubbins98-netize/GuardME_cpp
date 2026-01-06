#include "security/sslanalyzer.h"
#include "core/logger.h"
#include <QSslSocket>
#include <QSslConfiguration>
#include <QRegularExpression>

SslAnalyzer::SslResult SslAnalyzer::analyze(const QString& domain) {
    SslResult result;
    result.domain = domain;
    result.success = false;
    result.hasValidCert = false;
    
    QString cleanDomain = domain.toLower();
    cleanDomain.remove(QRegularExpression(R"(^https?://)"));
    cleanDomain = cleanDomain.split("/").first();
    cleanDomain = cleanDomain.split(":").first();
    
    QSslSocket socket;
    socket.connectToHostEncrypted(cleanDomain, 443);
    
    if (!socket.waitForEncrypted(10000)) {
        result.errorMessage = socket.errorString();
        Logger::getInstance().log(Logger::WARNING, 
            QString("SSL analysis failed for %1: %2").arg(domain, result.errorMessage));
        return result;
    }
    
    QSslCertificate cert = socket.peerCertificate();
    
    if (cert.isNull()) {
        result.errorMessage = "No certificate received";
        return result;
    }
    
    result.issuer = cert.issuerDisplayName();
    result.subject = cert.subjectDisplayName();
    result.validFrom = cert.effectiveDate();
    result.validUntil = cert.expiryDate();
    
    QDateTime now = QDateTime::currentDateTime();
    result.daysUntilExpiry = now.daysTo(result.validUntil);
    
    result.hasValidCert = now >= result.validFrom && now <= result.validUntil;
    
    if (!result.hasValidCert) {
        if (now < result.validFrom) {
            result.warnings << "Certificate not yet valid";
        } else {
            result.warnings << "Certificate has expired";
        }
    }
    
    if (result.daysUntilExpiry < 30 && result.daysUntilExpiry >= 0) {
        result.warnings << QString("Certificate expires in %1 days").arg(result.daysUntilExpiry);
    }
    
    if (result.issuer.contains("Self-Signed", Qt::CaseInsensitive) ||
        result.issuer == result.subject) {
        result.warnings << "Self-signed certificate detected";
    }
    
    socket.disconnectFromHost();
    
    result.success = true;
    
    Logger::getInstance().log(Logger::INFO, 
        QString("SSL analysis: %1 - Valid: %2, Expires: %3 days")
        .arg(domain)
        .arg(result.hasValidCert ? "Yes" : "No")
        .arg(result.daysUntilExpiry));
    
    return result;
}

bool SslAnalyzer::isCertificateValid(const SslResult& result) {
    return result.success && result.hasValidCert && result.daysUntilExpiry > 0;
}
