#include "security/urlanalyzer.h"
#include "core/configmanager.h"
#include "core/logger.h"
#include <QUrl>

UrlAnalyzer::UrlAnalyzer() {
    suspiciousKeywords << "login" << "signin" << "verify" << "secure" << "account"
                       << "update" << "confirm" << "banking" << "paypal" << "amazon"
                       << "ebay" << "apple" << "microsoft" << "google" << "facebook";
    
    suspiciousTlds << ".xyz" << ".top" << ".club" << ".work" << ".click"
                   << ".link" << ".tk" << ".ml" << ".ga" << ".cf" << ".gq";
    
    ipPattern = QRegularExpression(R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})");
}

QString UrlAnalyzer::extractDomain(const QString& url) {
    QUrl qurl(url);
    QString host = qurl.host();
    if (host.isEmpty()) {
        host = url;
        host.remove(QRegularExpression(R"(^https?://)"));
        host = host.split("/").first();
    }
    return host.toLower();
}

bool UrlAnalyzer::isWhitelisted(const QString& url) {
    QString domain = extractDomain(url);
    QStringList whitelist = ConfigManager::getInstance().getWhitelistedDomains();
    
    for (const QString& whitelistedDomain : whitelist) {
        if (domain.contains(whitelistedDomain) || whitelistedDomain.contains(domain)) {
            return true;
        }
    }
    return false;
}

bool UrlAnalyzer::hasIpAddress(const QString& host) {
    return ipPattern.match(host).hasMatch();
}

int UrlAnalyzer::countSpecialChars(const QString& url) {
    int count = 0;
    for (const QChar& c : url) {
        if (c == '@' || c == '-' || c == '_' || c == '~') {
            count++;
        }
    }
    return count;
}

bool UrlAnalyzer::hasSuspiciousPatterns(const QString& url) {
    QString lower = url.toLower();
    
    for (const QString& keyword : suspiciousKeywords) {
        if (lower.contains(keyword) && !isWhitelisted(url)) {
            return true;
        }
    }
    
    if (lower.count('.') > 4) return true;
    if (lower.count('-') > 3) return true;
    if (lower.contains("..")) return true;
    
    return false;
}

int UrlAnalyzer::calculateUrlScore(const QString& url) {
    int score = 0;
    QString lower = url.toLower();
    QUrl qurl(url);
    QString host = qurl.host();
    
    if (!qurl.scheme().isEmpty() && qurl.scheme() != "https") {
        score += 15;
    }
    
    if (hasIpAddress(host)) {
        score += 25;
    }
    
    for (const QString& tld : suspiciousTlds) {
        if (lower.endsWith(tld)) {
            score += 20;
            break;
        }
    }
    
    if (hasSuspiciousPatterns(url)) {
        score += 15;
    }
    
    if (url.length() > 75) {
        score += 10;
    }
    if (url.length() > 100) {
        score += 10;
    }
    
    int specialChars = countSpecialChars(url);
    if (specialChars > 3) {
        score += specialChars * 3;
    }
    
    if (lower.contains("@")) {
        score += 20;
    }
    
    if (lower.contains("%") && lower.contains("hex")) {
        score += 15;
    }
    
    return qMin(score, 100);
}

UrlAnalyzer::AnalysisResult UrlAnalyzer::analyzeUrl(const QString& url) {
    AnalysisResult result;
    result.isWhitelisted = isWhitelisted(url);
    
    if (result.isWhitelisted) {
        result.threatLevel = SAFE;
        result.threatLevelString = "SAFE";
        result.score = 0;
        result.details << "Domain is whitelisted";
        return result;
    }
    
    result.score = calculateUrlScore(url);
    
    if (result.score >= 75) {
        result.threatLevel = CRITICAL;
        result.threatLevelString = "CRITICAL";
    } else if (result.score >= 50) {
        result.threatLevel = HIGH;
        result.threatLevelString = "HIGH";
    } else if (result.score >= 30) {
        result.threatLevel = MEDIUM;
        result.threatLevelString = "MEDIUM";
    } else if (result.score >= 15) {
        result.threatLevel = LOW;
        result.threatLevelString = "LOW";
    } else {
        result.threatLevel = SAFE;
        result.threatLevelString = "SAFE";
    }
    
    QUrl qurl(url);
    
    if (qurl.scheme() != "https") {
        result.details << "Not using HTTPS (insecure connection)";
    }
    
    if (hasIpAddress(qurl.host())) {
        result.details << "URL uses IP address instead of domain name";
    }
    
    QString lower = url.toLower();
    for (const QString& tld : suspiciousTlds) {
        if (lower.endsWith(tld)) {
            result.details << QString("Uses suspicious TLD: %1").arg(tld);
            break;
        }
    }
    
    if (url.length() > 75) {
        result.details << "Unusually long URL";
    }
    
    if (hasSuspiciousPatterns(url)) {
        result.details << "Contains suspicious patterns or keywords";
    }
    
    if (result.details.isEmpty()) {
        result.details << "No significant threats detected";
    }
    
    Logger::getInstance().log(Logger::INFO, 
        QString("URL Analysis: %1 -> %2 (score: %3)").arg(url, result.threatLevelString).arg(result.score));
    
    return result;
}
