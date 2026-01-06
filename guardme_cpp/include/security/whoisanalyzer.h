#ifndef WHOISANALYZER_H
#define WHOISANALYZER_H

#include <QString>
#include <QDateTime>

class WhoisAnalyzer {
public:
    struct WhoisResult {
        QString domain;
        QString registrar;
        QString creationDate;
        QString expirationDate;
        QString updatedDate;
        QString nameServers;
        QString registrantCountry;
        int domainAge;
        bool success;
        QString errorMessage;
    };
    
    static WhoisAnalyzer& getInstance() {
        static WhoisAnalyzer instance;
        return instance;
    }
    
    WhoisResult lookup(const QString& domain);
    bool isSuspicious(const WhoisResult& result);
    
private:
    WhoisAnalyzer() = default;
    ~WhoisAnalyzer() = default;
    WhoisAnalyzer(const WhoisAnalyzer&) = delete;
    WhoisAnalyzer& operator=(const WhoisAnalyzer&) = delete;
    
    QString parseField(const QString& output, const QString& fieldName);
    int calculateDomainAge(const QString& creationDate);
};

#endif
