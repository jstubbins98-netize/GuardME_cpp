#ifndef BREACHCHECK_H
#define BREACHCHECK_H

#include <QString>
#include <QStringList>

class BreachCheck {
public:
    struct BreachResult {
        bool found;
        int breachCount;
        QStringList breachedSites;
        QString errorMessage;
    };
    
    struct PasswordResult {
        bool pwned;
        int occurrences;
        QString errorMessage;
    };
    
    static BreachCheck& getInstance() {
        static BreachCheck instance;
        return instance;
    }
    
    BreachResult checkEmail(const QString& email);
    PasswordResult checkPassword(const QString& password);
    
private:
    BreachCheck() = default;
    ~BreachCheck() = default;
    BreachCheck(const BreachCheck&) = delete;
    BreachCheck& operator=(const BreachCheck&) = delete;
    
    QString sha1Hash(const QString& input);
};

#endif
