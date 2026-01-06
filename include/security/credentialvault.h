#ifndef CREDENTIALVAULT_H
#define CREDENTIALVAULT_H

#include <QString>
#include <QMap>
#include <QByteArray>

class CredentialVault {
public:
    static CredentialVault& getInstance() {
        static CredentialVault instance;
        return instance;
    }
    
    bool storeCredential(const QString& service, const QString& username, const QString& password);
    bool getCredential(const QString& service, QString& username, QString& password);
    bool deleteCredential(const QString& service);
    QStringList listServices();
    
    bool setMasterPassword(const QString& password);
    bool verifyMasterPassword(const QString& password);
    bool isLocked() const { return locked; }
    bool isInitialized() const { return initialized; }
    bool hasStoredCredentials() const { return !credentials.isEmpty(); }
    void lock();
    bool unlock(const QString& password);
    void reset();
    
private:
    CredentialVault();
    ~CredentialVault() = default;
    CredentialVault(const CredentialVault&) = delete;
    CredentialVault& operator=(const CredentialVault&) = delete;
    
    QByteArray encrypt(const QString& plaintext);
    QString decrypt(const QByteArray& ciphertext);
    QByteArray deriveKey(const QString& password, const QByteArray& salt);
    void loadVault();
    void saveVault();
    
    struct Credential {
        QString username;
        QByteArray encryptedPassword;
    };
    
    QMap<QString, Credential> credentials;
    QByteArray masterKey;
    QByteArray salt;
    QByteArray passwordVerifier;
    QString vaultPath;
    bool locked;
    bool initialized;
};

#endif
