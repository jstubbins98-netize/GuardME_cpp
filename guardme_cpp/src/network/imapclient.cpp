#include "network/imapclient.h"
#include "core/logger.h"
#include <curl/curl.h>
#include <QRegularExpression>
#include <QUrl>
#include <algorithm>

ImapClient::ImapClient() : connected(false) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

ImapClient::~ImapClient() {
    disconnect();
    curl_global_cleanup();
}

size_t ImapClient::writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t totalSize = size * nmemb;
    QString* output = static_cast<QString*>(userp);
    output->append(QString::fromUtf8(static_cast<char*>(contents), totalSize));
    return totalSize;
}

bool ImapClient::connect(const ConnectionSettings& settings) {
    currentSettings = settings;
    
    CURL* curl = curl_easy_init();
    if (!curl) {
        lastError = "Failed to initialize connection";
        return false;
    }
    
    QString url = QString("imaps://%1:%2/INBOX")
                    .arg(settings.server)
                    .arg(settings.port > 0 ? settings.port : 993);
    
    QString response;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.toStdString().c_str());
    curl_easy_setopt(curl, CURLOPT_USERNAME, settings.email.toStdString().c_str());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, settings.password.toStdString().c_str());
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        lastError = QString("Connection failed: %1").arg(curl_easy_strerror(res));
        Logger::getInstance().log(Logger::ERROR_LEVEL, lastError);
        curl_easy_cleanup(curl);
        currentSettings.password.clear();
        return false;
    }
    
    curl_easy_cleanup(curl);
    connected = true;
    Logger::getInstance().log(Logger::SUCCESS, QString("Connected to %1").arg(settings.server));
    return true;
}

void ImapClient::disconnect() {
    connected = false;
    currentSettings.password.clear();
    currentSettings.email.clear();
    sessionData.clear();
    Logger::getInstance().log(Logger::INFO, "Disconnected from email server");
}

QList<ImapClient::EmailMessage> ImapClient::fetchEmails(int count) {
    QList<EmailMessage> emails;
    
    if (!connected) {
        lastError = "Not connected to server";
        return emails;
    }
    
    CURL* curl = curl_easy_init();
    if (!curl) {
        lastError = "Failed to initialize fetch";
        return emails;
    }
    
    QString searchUrl = QString("imaps://%1:%2/INBOX?UNSEEN")
                          .arg(currentSettings.server)
                          .arg(currentSettings.port > 0 ? currentSettings.port : 993);
    
    QString searchResponse;
    
    curl_easy_setopt(curl, CURLOPT_URL, searchUrl.toStdString().c_str());
    curl_easy_setopt(curl, CURLOPT_USERNAME, currentSettings.email.toStdString().c_str());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, currentSettings.password.toStdString().c_str());
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &searchResponse);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "SEARCH ALL");
    
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        QString listUrl = QString("imaps://%1:%2/INBOX")
                            .arg(currentSettings.server)
                            .arg(currentSettings.port > 0 ? currentSettings.port : 993);
        
        CURL* listCurl = curl_easy_init();
        QString listResponse;
        
        curl_easy_setopt(listCurl, CURLOPT_URL, listUrl.toStdString().c_str());
        curl_easy_setopt(listCurl, CURLOPT_USERNAME, currentSettings.email.toStdString().c_str());
        curl_easy_setopt(listCurl, CURLOPT_PASSWORD, currentSettings.password.toStdString().c_str());
        curl_easy_setopt(listCurl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
        curl_easy_setopt(listCurl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(listCurl, CURLOPT_WRITEDATA, &listResponse);
        curl_easy_setopt(listCurl, CURLOPT_TIMEOUT, 30L);
        
        res = curl_easy_perform(listCurl);
        curl_easy_cleanup(listCurl);
        
        if (res != CURLE_OK) {
            lastError = QString("Failed to list emails: %1").arg(curl_easy_strerror(res));
            return emails;
        }
        searchResponse = listResponse;
    }
    
    QRegularExpression seqRegex(R"(\b(\d+)\b)");
    QRegularExpressionMatchIterator i = seqRegex.globalMatch(searchResponse);
    QList<int> messageIds;
    
    while (i.hasNext()) {
        QRegularExpressionMatch match = i.next();
        int seqNum = match.captured(1).toInt();
        if (seqNum > 0 && !messageIds.contains(seqNum)) {
            messageIds.append(seqNum);
        }
    }
    
    std::sort(messageIds.begin(), messageIds.end(), std::greater<int>());
    
    if (messageIds.isEmpty()) {
        for (int id = 1; id <= qMin(count, 10); id++) {
            messageIds.append(id);
        }
    }
    
    for (int msgId : messageIds) {
        if (emails.size() >= count) break;
        EmailMessage msg = fetchEmailById(msgId);
        if (!msg.subject.isEmpty() || !msg.from.isEmpty()) {
            emails.append(msg);
        }
    }
    
    Logger::getInstance().log(Logger::INFO, QString("Fetched %1 emails").arg(emails.size()));
    return emails;
}

ImapClient::EmailMessage ImapClient::fetchEmailById(int id) {
    EmailMessage email;
    email.id = id;
    email.hasAttachments = false;
    
    if (!connected) {
        return email;
    }
    
    CURL* curl = curl_easy_init();
    if (!curl) {
        return email;
    }
    
    // MAILINDEX=N fetches by sequence number (returned by SEARCH ALL)
    // Use UID=N if fetching by UID (requires UID SEARCH ALL)
    QString fetchUrl = QString("imaps://%1:%2/INBOX/;MAILINDEX=%3")
                         .arg(currentSettings.server)
                         .arg(currentSettings.port > 0 ? currentSettings.port : 993)
                         .arg(id);
    
    QString response;
    
    curl_easy_setopt(curl, CURLOPT_URL, fetchUrl.toStdString().c_str());
    curl_easy_setopt(curl, CURLOPT_USERNAME, currentSettings.email.toStdString().c_str());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, currentSettings.password.toStdString().c_str());
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res == CURLE_OK && !response.isEmpty()) {
        email.from = extractHeader(response, "From");
        email.to = extractHeader(response, "To");
        email.subject = extractHeader(response, "Subject");
        email.date = extractHeader(response, "Date");
        email.body = extractBody(response);
        
        QString contentType = extractHeader(response, "Content-Type");
        email.hasAttachments = contentType.contains("multipart/mixed", Qt::CaseInsensitive);
    }
    
    return email;
}

QString ImapClient::extractHeader(const QString& raw, const QString& headerName) {
    QRegularExpression regex(headerName + R"(:\s*(.+?)(?:\r?\n(?!\s)))", 
                             QRegularExpression::CaseInsensitiveOption | 
                             QRegularExpression::MultilineOption);
    QRegularExpressionMatch match = regex.match(raw);
    
    if (match.hasMatch()) {
        QString value = match.captured(1).trimmed();
        value.replace(QRegularExpression(R"(\r?\n\s+)"), " ");
        return value;
    }
    return QString();
}

QString ImapClient::extractBody(const QString& raw) {
    int headerEnd = raw.indexOf("\r\n\r\n");
    if (headerEnd == -1) {
        headerEnd = raw.indexOf("\n\n");
    }
    
    if (headerEnd != -1) {
        QString body = raw.mid(headerEnd + 4);
        
        body.remove(QRegularExpression("<[^>]*>"));
        body = body.trimmed();
        
        if (body.length() > 2000) {
            body = body.left(2000) + "...";
        }
        
        return body;
    }
    
    return QString();
}

QStringList ImapClient::extractLinks(const QString& text) {
    QStringList links;
    QRegularExpression urlRegex(R"((https?://[^\s<>"']+))");
    QRegularExpressionMatchIterator i = urlRegex.globalMatch(text);
    
    while (i.hasNext()) {
        QRegularExpressionMatch match = i.next();
        links << match.captured(1);
    }
    
    return links;
}

bool ImapClient::isSuspiciousLink(const QString& url) {
    QUrl parsedUrl(url);
    QString host = parsedUrl.host().toLower();
    
    QStringList suspiciousTlds = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click", ".link"};
    for (const QString& tld : suspiciousTlds) {
        if (host.endsWith(tld)) return true;
    }
    
    QRegularExpression ipRegex(R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})");
    if (ipRegex.match(host).hasMatch()) return true;
    
    if (host.count('.') > 4) return true;
    
    QStringList phishingKeywords = {"login", "verify", "account", "secure", "update", "confirm", 
                                     "banking", "paypal", "amazon", "microsoft", "apple"};
    for (const QString& keyword : phishingKeywords) {
        if (host.contains(keyword) && !host.endsWith(".com") && !host.endsWith(".org")) {
            return true;
        }
    }
    
    return false;
}

bool ImapClient::hasPhishingKeywords(const QString& text) {
    QString lowerText = text.toLower();
    
    QStringList urgentPhrases = {
        "urgent action required",
        "your account will be suspended",
        "verify your identity immediately",
        "click here to confirm",
        "you have been selected",
        "act now",
        "limited time offer",
        "confirm your password",
        "your account has been compromised",
        "unauthorized access detected"
    };
    
    for (const QString& phrase : urgentPhrases) {
        if (lowerText.contains(phrase)) return true;
    }
    
    return false;
}

ImapClient::AnalysisResult ImapClient::analyzeEmail(const EmailMessage& email) {
    AnalysisResult result;
    result.spamScore = 0;
    result.riskLevel = "Low";
    result.hasSuspiciousLinks = false;
    result.hasPhishingIndicators = false;
    result.senderVerified = true;
    
    QStringList links = extractLinks(email.body);
    for (const QString& link : links) {
        if (isSuspiciousLink(link)) {
            result.hasSuspiciousLinks = true;
            result.warnings << QString("Suspicious link detected: %1").arg(link);
            result.spamScore += 25;
        }
    }
    
    if (hasPhishingKeywords(email.subject) || hasPhishingKeywords(email.body)) {
        result.hasPhishingIndicators = true;
        result.warnings << "Phishing keywords detected in message";
        result.spamScore += 30;
    }
    
    if (email.from.contains("noreply") || email.from.contains("no-reply")) {
        result.spamScore += 5;
    }
    
    QRegularExpression senderMismatch(R"(<([^>]+)>)");
    QRegularExpressionMatch match = senderMismatch.match(email.from);
    if (match.hasMatch()) {
        QString emailAddr = match.captured(1);
        QString displayName = email.from.left(email.from.indexOf('<')).trimmed();
        
        if (!displayName.isEmpty() && !emailAddr.contains(displayName.split(' ').first(), Qt::CaseInsensitive)) {
            result.senderVerified = false;
            result.warnings << "Sender display name doesn't match email address";
            result.spamScore += 15;
        }
    }
    
    if (email.hasAttachments) {
        result.warnings << "Email contains attachments - verify sender before opening";
        result.spamScore += 10;
    }
    
    if (result.spamScore >= 50) {
        result.riskLevel = "High";
    } else if (result.spamScore >= 25) {
        result.riskLevel = "Medium";
    } else {
        result.riskLevel = "Low";
    }
    
    if (result.warnings.isEmpty()) {
        result.warnings << "No security issues detected";
    }
    
    return result;
}
