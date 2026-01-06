#include "core/logger.h"

Logger::Logger() : fileLoggingEnabled(false) {}

Logger::~Logger() {
    if (logFile.isOpen()) {
        logFile.close();
    }
}

void Logger::setLogFile(const QString& filename) {
    QMutexLocker locker(&mutex);
    if (logFile.isOpen()) {
        logFile.close();
    }
    logFile.setFileName(filename);
    fileLoggingEnabled = logFile.open(QIODevice::Append | QIODevice::Text);
}

QString Logger::getLevelString(Level level) {
    switch (level) {
        case DEBUG: return "DEBUG";
        case INFO: return "INFO";
        case WARNING: return "WARNING";
        case ERROR_LEVEL: return "ERROR";
        case SUCCESS: return "SUCCESS";
        default: return "UNKNOWN";
    }
}

void Logger::log(Level level, const QString& message) {
    QMutexLocker locker(&mutex);
    
    QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
    QString levelStr = getLevelString(level);
    QString logMessage = QString("[%1] [%2] %3").arg(timestamp, levelStr, message);
    
    std::cout << logMessage.toStdString() << std::endl;
    
    if (fileLoggingEnabled && logFile.isOpen()) {
        QTextStream stream(&logFile);
        stream << logMessage << "\n";
        stream.flush();
    }
}
