#ifndef ALERTSTAB_H
#define ALERTSTAB_H

#include <QWidget>
#include <QListWidget>
#include <QPushButton>
#include <QTextEdit>
#include <QLabel>

class AlertsTab : public QWidget {
    Q_OBJECT

public:
    explicit AlertsTab(QWidget *parent = nullptr);
    void addAlert(const QString& type, const QString& message, const QString& severity);

private slots:
    void clearAlerts();
    void showAlertDetails();
    void exportAlerts();

private:
    void setupUI();
    
    QListWidget *alertsList;
    QTextEdit *alertDetailsText;
    QLabel *alertCountLabel;
    
    struct Alert {
        QString type;
        QString message;
        QString severity;
        QString timestamp;
    };
    QList<Alert> alerts;
};

#endif
