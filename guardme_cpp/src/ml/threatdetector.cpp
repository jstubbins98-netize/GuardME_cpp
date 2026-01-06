#include "ml/threatdetector.h"
#include "core/logger.h"
#include <QFile>
#include <QFileInfo>
#include <QUrl>
#include <QtMath>
#include <QRegularExpression>

ThreatDetector::ThreatDetector() {
    maliciousPatterns << "eval(" << "exec(" << "base64_decode" << "fromCharCode"
                      << "document.write" << "unescape" << "shell_exec" << "system(";
    
    dangerousExtensions << ".exe" << ".bat" << ".cmd" << ".scr" << ".pif"
                        << ".vbs" << ".js" << ".jar" << ".msi" << ".dll"
                        << ".ps1" << ".hta" << ".wsf" << ".cpl";
}

double ThreatDetector::calculateEntropy(const QByteArray& data) {
    if (data.isEmpty()) return 0.0;
    
    QMap<unsigned char, int> frequency;
    for (unsigned char byte : data) {
        frequency[byte]++;
    }
    
    double entropy = 0.0;
    int length = data.size();
    
    for (int count : frequency.values()) {
        double probability = static_cast<double>(count) / length;
        entropy -= probability * qLn(probability) / qLn(2.0);
    }
    
    return entropy;
}

QString ThreatDetector::scoreToRiskLevel(double score) {
    if (score >= 0.8) return "CRITICAL";
    if (score >= 0.6) return "HIGH";
    if (score >= 0.4) return "MEDIUM";
    if (score >= 0.2) return "LOW";
    return "SAFE";
}

double ThreatDetector::extractUrlFeatures(const QString& url, QStringList& indicators) {
    double score = 0.0;
    QUrl qurl(url);
    QString host = qurl.host().toLower();
    QString path = qurl.path().toLower();
    QString full = url.toLower();
    
    if (qurl.scheme() != "https") {
        score += 0.1;
        indicators << "Not using HTTPS";
    }
    
    QRegularExpression ipRegex(R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})");
    if (ipRegex.match(host).hasMatch()) {
        score += 0.25;
        indicators << "IP address used instead of domain";
    }
    
    if (url.length() > 100) {
        score += 0.15;
        indicators << "Unusually long URL";
    }
    
    if (host.count('.') > 4) {
        score += 0.15;
        indicators << "Excessive subdomains";
    }
    
    if (full.contains('@')) {
        score += 0.2;
        indicators << "Contains @ symbol";
    }
    
    QStringList suspiciousKeywords = {"login", "signin", "verify", "secure", "account", 
                                       "update", "confirm", "banking", "password"};
    for (const QString& keyword : suspiciousKeywords) {
        if (path.contains(keyword) && !host.contains("google") && !host.contains("microsoft")) {
            score += 0.1;
            indicators << QString("Suspicious keyword: %1").arg(keyword);
            break;
        }
    }
    
    QStringList suspiciousTlds = {".xyz", ".top", ".club", ".tk", ".ml", ".ga"};
    for (const QString& tld : suspiciousTlds) {
        if (host.endsWith(tld)) {
            score += 0.2;
            indicators << QString("Suspicious TLD: %1").arg(tld);
            break;
        }
    }
    
    return qBound(0.0, score, 1.0);
}

double ThreatDetector::extractFileFeatures(const QString& filePath, QStringList& indicators) {
    double score = 0.0;
    
    QFileInfo fileInfo(filePath);
    QString ext = "." + fileInfo.suffix().toLower();
    
    if (dangerousExtensions.contains(ext)) {
        score += 0.3;
        indicators << QString("Dangerous file extension: %1").arg(ext);
    }
    
    QString name = fileInfo.fileName().toLower();
    if (name.contains("invoice") || name.contains("payment") || 
        name.contains("receipt") || name.contains("document")) {
        score += 0.1;
        indicators << "Suspicious filename pattern";
    }
    
    if (name.count('.') > 1) {
        score += 0.15;
        indicators << "Double extension detected";
    }
    
    QFile file(filePath);
    if (file.open(QIODevice::ReadOnly)) {
        QByteArray header = file.read(8192);
        file.close();
        
        double entropy = calculateEntropy(header);
        if (entropy > 7.5) {
            score += 0.2;
            indicators << QString("High entropy: %1").arg(entropy, 0, 'f', 2);
        }
        
        for (const QString& pattern : maliciousPatterns) {
            if (header.contains(pattern.toUtf8())) {
                score += 0.25;
                indicators << QString("Malicious pattern found: %1").arg(pattern);
                break;
            }
        }
    }
    
    return qBound(0.0, score, 1.0);
}

ThreatDetector::ThreatAssessment ThreatDetector::assessUrl(const QString& url) {
    ThreatAssessment assessment;
    
    double urlScore = extractUrlFeatures(url, assessment.indicators);
    
    assessment.componentScores["url_analysis"] = urlScore;
    assessment.overallScore = urlScore;
    assessment.riskLevel = scoreToRiskLevel(assessment.overallScore);
    
    Logger::getInstance().log(Logger::INFO, 
        QString("URL Threat Assessment: %1 -> %2 (score: %3)")
        .arg(url, assessment.riskLevel)
        .arg(assessment.overallScore, 0, 'f', 2));
    
    return assessment;
}

ThreatDetector::ThreatAssessment ThreatDetector::assessFile(const QString& filePath) {
    ThreatAssessment assessment;
    
    double fileScore = extractFileFeatures(filePath, assessment.indicators);
    
    assessment.componentScores["file_analysis"] = fileScore;
    assessment.overallScore = fileScore;
    assessment.riskLevel = scoreToRiskLevel(assessment.overallScore);
    
    Logger::getInstance().log(Logger::INFO, 
        QString("File Threat Assessment: %1 -> %2 (score: %3)")
        .arg(filePath, assessment.riskLevel)
        .arg(assessment.overallScore, 0, 'f', 2));
    
    return assessment;
}
