#ifndef HTTPCLIENT_H
#define HTTPCLIENT_H

#include <QString>
#include <QByteArray>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QEventLoop>

class HttpClient {
public:
    struct Response {
        int statusCode;
        QByteArray body;
        QString errorMessage;
        bool success;
    };
    
    static HttpClient& getInstance() {
        static HttpClient instance;
        return instance;
    }
    
    Response get(const QString& url, int timeout = 30000);
    Response post(const QString& url, const QByteArray& data, const QString& contentType = "application/json", int timeout = 30000);
    
private:
    HttpClient();
    ~HttpClient() = default;
    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;
    
    QNetworkAccessManager *manager;
};

#endif
