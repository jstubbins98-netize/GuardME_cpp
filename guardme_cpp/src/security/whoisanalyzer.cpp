#include "security/whoisanalyzer.h"
#include "core/logger.h"
#include <QProcess>
#include <QRegularExpression>
#include <QDate>

WhoisAnalyzer::WhoisResult WhoisAnalyzer::lookup(const QString& domain) {
    WhoisResult result;
    result.domain = domain;
    result.success = false;
    result.domainAge = 0;
    
    QString cleanDomain = domain.toLower();
    cleanDomain.remove(QRegularExpression(R"(^https?://)"));
    cleanDomain = cleanDomain.split("/").first();
    cleanDomain = cleanDomain.split(":").first();
    
    QProcess process;
    process.start("whois", {cleanDomain});
    
    if (!process.waitForFinished(30000)) {
        result.errorMessage = "WHOIS lookup timeout";
        return result;
    }
    
    QString output = QString::fromUtf8(process.readAllStandardOutput());
    
    if (output.isEmpty() || output.contains("No match for")) {
        result.errorMessage = "Domain not found";
        return result;
    }
    
    result.registrar = parseField(output, "Registrar:");
    if (result.registrar.isEmpty()) {
        result.registrar = parseField(output, "registrar:");
    }
    
    result.creationDate = parseField(output, "Creation Date:");
    if (result.creationDate.isEmpty()) {
        result.creationDate = parseField(output, "created:");
    }
    
    result.expirationDate = parseField(output, "Registry Expiry Date:");
    if (result.expirationDate.isEmpty()) {
        result.expirationDate = parseField(output, "Expiration Date:");
    }
    
    result.updatedDate = parseField(output, "Updated Date:");
    if (result.updatedDate.isEmpty()) {
        result.updatedDate = parseField(output, "last-modified:");
    }
    
    result.nameServers = parseField(output, "Name Server:");
    result.registrantCountry = parseField(output, "Registrant Country:");
    
    result.domainAge = calculateDomainAge(result.creationDate);
    
    result.success = true;
    
    Logger::getInstance().log(Logger::INFO, 
        QString("WHOIS lookup: %1 - Age: %2 days").arg(domain).arg(result.domainAge));
    
    return result;
}

QString WhoisAnalyzer::parseField(const QString& output, const QString& fieldName) {
    QStringList lines = output.split('\n');
    
    for (const QString& line : lines) {
        if (line.trimmed().startsWith(fieldName, Qt::CaseInsensitive)) {
            QString value = line.mid(line.indexOf(':') + 1).trimmed();
            return value;
        }
    }
    
    return QString();
}

int WhoisAnalyzer::calculateDomainAge(const QString& creationDate) {
    if (creationDate.isEmpty()) return -1;
    
    QStringList formats = {
        "yyyy-MM-dd",
        "yyyy-MM-ddTHH:mm:ssZ",
        "dd-MMM-yyyy",
        "yyyy.MM.dd",
        "dd/MM/yyyy"
    };
    
    QDate created;
    for (const QString& format : formats) {
        created = QDate::fromString(creationDate.left(10), format);
        if (created.isValid()) break;
    }
    
    if (!created.isValid()) {
        created = QDate::fromString(creationDate.left(10), Qt::ISODate);
    }
    
    if (created.isValid()) {
        return created.daysTo(QDate::currentDate());
    }
    
    return -1;
}

bool WhoisAnalyzer::isSuspicious(const WhoisResult& result) {
    if (result.domainAge >= 0 && result.domainAge < 30) {
        return true;
    }
    
    if (result.registrar.contains("privacy", Qt::CaseInsensitive) ||
        result.registrar.contains("proxy", Qt::CaseInsensitive)) {
        return true;
    }
    
    return false;
}
