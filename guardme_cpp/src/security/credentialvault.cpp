#include "security/credentialvault.h"
#include "core/logger.h"
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QDataStream>
#include <openssl/evp.h>
#include <openssl/rand.h>

CredentialVault::CredentialVault() : locked(true), initialized(false) {
    QString dataDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dataDir);
    vaultPath = dataDir + "/credential_vault.enc";
    
    salt.resize(32);
    RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), salt.size());
    
    loadVault();
}

QByteArray CredentialVault::deriveKey(const QString& password, const QByteArray& salt) {
    QByteArray key(32, 0);
    QByteArray passBytes = password.toUtf8();
    
    PKCS5_PBKDF2_HMAC(passBytes.constData(), passBytes.size(),
                       reinterpret_cast<const unsigned char*>(salt.constData()), salt.size(),
                       100000, EVP_sha256(),
                       key.size(), reinterpret_cast<unsigned char*>(key.data()));
    
    return key;
}

QByteArray CredentialVault::encrypt(const QString& plaintext) {
    if (locked || masterKey.isEmpty()) return QByteArray();
    
    QByteArray iv(16, 0);
    RAND_bytes(reinterpret_cast<unsigned char*>(iv.data()), iv.size());
    
    QByteArray plaintextBytes = plaintext.toUtf8();
    QByteArray ciphertext(plaintextBytes.size() + EVP_MAX_BLOCK_LENGTH, 0);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                       reinterpret_cast<const unsigned char*>(masterKey.constData()),
                       reinterpret_cast<const unsigned char*>(iv.constData()));
    
    int outLen1 = 0, outLen2 = 0;
    EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()), &outLen1,
                      reinterpret_cast<const unsigned char*>(plaintextBytes.constData()),
                      plaintextBytes.size());
    EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()) + outLen1, &outLen2);
    
    EVP_CIPHER_CTX_free(ctx);
    
    ciphertext.resize(outLen1 + outLen2);
    return iv + ciphertext;
}

QString CredentialVault::decrypt(const QByteArray& ciphertext) {
    if (locked || masterKey.isEmpty() || ciphertext.size() < 17) return QString();
    
    QByteArray iv = ciphertext.left(16);
    QByteArray encrypted = ciphertext.mid(16);
    
    QByteArray plaintext(encrypted.size() + EVP_MAX_BLOCK_LENGTH, 0);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                       reinterpret_cast<const unsigned char*>(masterKey.constData()),
                       reinterpret_cast<const unsigned char*>(iv.constData()));
    
    int outLen1 = 0, outLen2 = 0;
    EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plaintext.data()), &outLen1,
                      reinterpret_cast<const unsigned char*>(encrypted.constData()),
                      encrypted.size());
    
    int result = EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plaintext.data()) + outLen1, &outLen2);
    EVP_CIPHER_CTX_free(ctx);
    
    if (result != 1) return QString();
    
    plaintext.resize(outLen1 + outLen2);
    return QString::fromUtf8(plaintext);
}

void CredentialVault::loadVault() {
    QFile file(vaultPath);
    if (!file.exists()) {
        initialized = false;
        return;
    }
    
    if (file.open(QIODevice::ReadOnly)) {
        QDataStream stream(&file);
        
        quint32 magic;
        stream >> magic;
        if (magic != 0x47555244) {
            file.close();
            initialized = false;
            return;
        }
        
        stream >> salt >> passwordVerifier;
        
        int count;
        stream >> count;
        
        for (int i = 0; i < count; i++) {
            QString service;
            Credential cred;
            stream >> service >> cred.username >> cred.encryptedPassword;
            credentials[service] = cred;
        }
        
        file.close();
        initialized = true;
        Logger::getInstance().log(Logger::INFO, QString("Vault loaded with %1 credentials").arg(count));
    }
}

void CredentialVault::saveVault() {
    QFile file(vaultPath);
    if (file.open(QIODevice::WriteOnly)) {
        QDataStream stream(&file);
        
        stream << quint32(0x47555244);
        stream << salt << passwordVerifier;
        stream << static_cast<int>(credentials.size());
        
        for (auto it = credentials.begin(); it != credentials.end(); ++it) {
            stream << it.key() << it.value().username << it.value().encryptedPassword;
        }
        
        file.close();
        file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    }
}

bool CredentialVault::setMasterPassword(const QString& password) {
    salt.resize(32);
    RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), salt.size());
    
    masterKey = deriveKey(password, salt);
    
    QByteArray verifierSalt(16, 0);
    RAND_bytes(reinterpret_cast<unsigned char*>(verifierSalt.data()), verifierSalt.size());
    passwordVerifier = verifierSalt + deriveKey(password, verifierSalt);
    
    locked = false;
    initialized = true;
    
    saveVault();
    Logger::getInstance().log(Logger::SUCCESS, "Master password set");
    return true;
}

bool CredentialVault::verifyMasterPassword(const QString& password) {
    if (passwordVerifier.size() < 48) return false;
    
    QByteArray storedSalt = passwordVerifier.left(16);
    QByteArray storedHash = passwordVerifier.mid(16);
    QByteArray derivedHash = deriveKey(password, storedSalt);
    
    return derivedHash == storedHash;
}

void CredentialVault::lock() {
    locked = true;
    masterKey.fill('\0');
    masterKey.clear();
}

bool CredentialVault::unlock(const QString& password) {
    if (!verifyMasterPassword(password)) {
        Logger::getInstance().log(Logger::WARNING, "Invalid master password");
        return false;
    }
    
    masterKey = deriveKey(password, salt);
    locked = false;
    Logger::getInstance().log(Logger::SUCCESS, "Vault unlocked");
    return true;
}

bool CredentialVault::storeCredential(const QString& service, const QString& username, const QString& password) {
    if (locked) return false;
    
    Credential cred;
    cred.username = username;
    cred.encryptedPassword = encrypt(password);
    
    credentials[service] = cred;
    saveVault();
    
    Logger::getInstance().log(Logger::INFO, QString("Credential stored for: %1").arg(service));
    return true;
}

bool CredentialVault::getCredential(const QString& service, QString& username, QString& password) {
    if (locked || !credentials.contains(service)) return false;
    
    const Credential& cred = credentials[service];
    username = cred.username;
    password = decrypt(cred.encryptedPassword);
    
    return !password.isEmpty();
}

bool CredentialVault::deleteCredential(const QString& service) {
    if (credentials.remove(service) > 0) {
        saveVault();
        Logger::getInstance().log(Logger::INFO, QString("Credential deleted: %1").arg(service));
        return true;
    }
    return false;
}

QStringList CredentialVault::listServices() {
    return credentials.keys();
}

void CredentialVault::reset() {
    lock();
    
    credentials.clear();
    passwordVerifier.clear();
    
    salt.resize(32);
    RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), salt.size());
    
    QFile file(vaultPath);
    if (file.exists()) {
        file.remove();
    }
    
    initialized = false;
    
    Logger::getInstance().log(Logger::INFO, "Credential vault reset");
}
