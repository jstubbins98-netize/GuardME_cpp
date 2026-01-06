#ifndef URLANALYZER_H
#define URLANALYZER_H

#include <QString>
#include <QStringList>
#include <QUrl>
#include <QRegularExpression>

class UrlAnalyzer {
public:
    enum ThreatLevel { SAFE, LOW, MEDIUM, HIGH, CRITICAL };
    
    struct AnalysisResult {
        ThreatLevel threatLevel;
        QString threatLevelString;
        int score;
        QStringList details;
        bool isWhitelisted;
    };
    
    static UrlAnalyzer& getInstance() {
        static UrlAnalyzer instance;
        return instance;
    }
    
    AnalysisResult analyzeUrl(const QString& url);
    bool isWhitelisted(const QString& url);
    
private:
    UrlAnalyzer();
    ~UrlAnalyzer() = default;
    UrlAnalyzer(const UrlAnalyzer&) = delete;
    UrlAnalyzer& operator=(const UrlAnalyzer&) = delete;
    
    int calculateUrlScore(const QString& url);
    bool hasSuspiciousPatterns(const QString& url);
    bool hasIpAddress(const QString& host);
    int countSpecialChars(const QString& url);
    QString extractDomain(const QString& url);
    
    QStringList suspiciousKeywords;
    QStringList suspiciousTlds;
    QRegularExpression ipPattern;
};

#endif
