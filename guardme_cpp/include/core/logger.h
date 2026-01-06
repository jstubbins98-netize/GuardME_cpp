#ifndef LOGGER_H
#define LOGGER_H

#include <QString>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QMutex>
#include <iostream>

class Logger {
public:
    enum Level { DEBUG, INFO, WARNING, ERROR_LEVEL, SUCCESS };
    
    static Logger& getInstance() {
        static Logger instance;
        return instance;
    }
    
    void log(Level level, const QString& message);
    void setLogFile(const QString& filename);
    QString getLevelString(Level level);
    
private:
    Logger();
    ~Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    QFile logFile;
    QMutex mutex;
    bool fileLoggingEnabled;
};

#endif
