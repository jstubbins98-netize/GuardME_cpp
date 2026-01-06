#include "network/breachcheck.h"
#include "network/httpclient.h"
#include "core/logger.h"
#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>

QString BreachCheck::sha1Hash(const QString& input) {
    QByteArray hash = QCryptographicHash::hash(input.toUtf8(), QCryptographicHash::Sha1);
    return hash.toHex().toUpper();
}

BreachCheck::BreachResult BreachCheck::checkEmail(const QString& email) {
    BreachResult result;
    result.found = false;
    result.breachCount = 0;
    
    QString url = QString("https://haveibeenpwned.com/api/v3/breachedaccount/%1").arg(email);
    
    HttpClient::Response response = HttpClient::getInstance().get(url);
    
    if (!response.success) {
        if (response.statusCode == 404) {
            result.found = false;
            Logger::getInstance().log(Logger::INFO, 
                QString("No breaches found for email: %1").arg(email));
            return result;
        }
        
        result.errorMessage = response.errorMessage;
        Logger::getInstance().log(Logger::WARNING, 
            QString("Email breach check failed: %1").arg(response.errorMessage));
        return result;
    }
    
    QJsonDocument doc = QJsonDocument::fromJson(response.body);
    if (doc.isArray()) {
        QJsonArray breaches = doc.array();
        result.found = !breaches.isEmpty();
        result.breachCount = breaches.size();
        
        for (const QJsonValue& breach : breaches) {
            QJsonObject obj = breach.toObject();
            result.breachedSites << obj["Name"].toString();
        }
    }
    
    Logger::getInstance().log(result.found ? Logger::WARNING : Logger::SUCCESS, 
        QString("Email breach check: %1 - %2 breaches").arg(email).arg(result.breachCount));
    
    return result;
}

BreachCheck::PasswordResult BreachCheck::checkPassword(const QString& password) {
    PasswordResult result;
    result.pwned = false;
    result.occurrences = 0;
    
    QString hash = sha1Hash(password);
    QString prefix = hash.left(5);
    QString suffix = hash.mid(5);
    
    QString url = QString("https://api.pwnedpasswords.com/range/%1").arg(prefix);
    
    HttpClient::Response response = HttpClient::getInstance().get(url);
    
    if (!response.success) {
        result.errorMessage = response.errorMessage;
        Logger::getInstance().log(Logger::WARNING, 
            QString("Password breach check failed: %1").arg(response.errorMessage));
        return result;
    }
    
    QString responseText = QString::fromUtf8(response.body);
    QStringList lines = responseText.split("\r\n", Qt::SkipEmptyParts);
    
    for (const QString& line : lines) {
        QStringList parts = line.split(':');
        if (parts.size() == 2) {
            if (parts[0].toUpper() == suffix) {
                result.pwned = true;
                result.occurrences = parts[1].toInt();
                break;
            }
        }
    }
    
    Logger::getInstance().log(result.pwned ? Logger::WARNING : Logger::SUCCESS, 
        QString("Password breach check: %1 in %2 breaches")
        .arg(result.pwned ? "Found" : "Not found")
        .arg(result.occurrences));
    
    return result;
}
