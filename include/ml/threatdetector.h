#ifndef THREATDETECTOR_H
#define THREATDETECTOR_H

#include <QString>
#include <QStringList>
#include <QMap>

class ThreatDetector {
public:
    struct ThreatAssessment {
        double overallScore;
        QString riskLevel;
        QStringList indicators;
        QMap<QString, double> componentScores;
    };
    
    static ThreatDetector& getInstance() {
        static ThreatDetector instance;
        return instance;
    }
    
    ThreatAssessment assessUrl(const QString& url);
    ThreatAssessment assessFile(const QString& filePath);
    double calculateEntropy(const QByteArray& data);
    
private:
    ThreatDetector();
    ~ThreatDetector() = default;
    ThreatDetector(const ThreatDetector&) = delete;
    ThreatDetector& operator=(const ThreatDetector&) = delete;
    
    double extractUrlFeatures(const QString& url, QStringList& indicators);
    double extractFileFeatures(const QString& filePath, QStringList& indicators);
    QString scoreToRiskLevel(double score);
    
    QStringList maliciousPatterns;
    QStringList dangerousExtensions;
};

#endif
