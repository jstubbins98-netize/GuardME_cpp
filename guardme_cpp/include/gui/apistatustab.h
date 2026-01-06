#ifndef APISTATUSTAB_H
#define APISTATUSTAB_H

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <QGridLayout>

class ApiStatusTab : public QWidget {
    Q_OBJECT

public:
    explicit ApiStatusTab(QWidget *parent = nullptr);

private slots:
    void refreshStatus();
    void checkAllServices();

private:
    void setupUI();
    QWidget* createServiceCard(const QString& name, const QString& description);
    void updateServiceStatus(const QString& name, bool isOnline, const QString& latency = "");
    
    QMap<QString, QLabel*> statusLabels;
    QMap<QString, QLabel*> latencyLabels;
    QTimer *refreshTimer;
};

#endif
