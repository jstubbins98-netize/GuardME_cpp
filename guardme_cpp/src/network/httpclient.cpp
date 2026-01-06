#include "network/httpclient.h"
#include "core/logger.h"
#include <QNetworkRequest>
#include <QTimer>

HttpClient::HttpClient() {
    manager = new QNetworkAccessManager();
}

HttpClient::Response HttpClient::get(const QString& url, int timeout) {
    Response response;
    response.success = false;
    response.statusCode = 0;
    
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::UserAgentHeader, "GuardME/1.0");
    
    QNetworkReply *reply = manager->get(request);
    
    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    
    timer.start(timeout);
    loop.exec();
    
    if (timer.isActive()) {
        timer.stop();
        
        if (reply->error() == QNetworkReply::NoError) {
            response.success = true;
            response.statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            response.body = reply->readAll();
        } else {
            response.errorMessage = reply->errorString();
            Logger::getInstance().log(Logger::ERROR_LEVEL, 
                QString("HTTP GET failed: %1 - %2").arg(url, response.errorMessage));
        }
    } else {
        response.errorMessage = "Request timeout";
        reply->abort();
    }
    
    reply->deleteLater();
    return response;
}

HttpClient::Response HttpClient::post(const QString& url, const QByteArray& data, 
                                       const QString& contentType, int timeout) {
    Response response;
    response.success = false;
    response.statusCode = 0;
    
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::UserAgentHeader, "GuardME/1.0");
    request.setHeader(QNetworkRequest::ContentTypeHeader, contentType);
    
    QNetworkReply *reply = manager->post(request, data);
    
    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    
    timer.start(timeout);
    loop.exec();
    
    if (timer.isActive()) {
        timer.stop();
        
        if (reply->error() == QNetworkReply::NoError) {
            response.success = true;
            response.statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            response.body = reply->readAll();
        } else {
            response.errorMessage = reply->errorString();
            Logger::getInstance().log(Logger::ERROR_LEVEL, 
                QString("HTTP POST failed: %1 - %2").arg(url, response.errorMessage));
        }
    } else {
        response.errorMessage = "Request timeout";
        reply->abort();
    }
    
    reply->deleteLater();
    return response;
}
