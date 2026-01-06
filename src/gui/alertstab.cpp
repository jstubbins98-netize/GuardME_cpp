#include "gui/alertstab.h"
#include "core/logger.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QScrollArea>
#include <QFrame>
#include <QSplitter>
#include <QDateTime>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <QMessageBox>

AlertsTab::AlertsTab(QWidget *parent) : QWidget(parent) {
    setupUI();
    
    addAlert("System", "GuardME started successfully", "info");
    addAlert("URL Monitor", "URL monitoring service activated", "info");
    addAlert("Virus Scanner", "ClamAV engine ready", "info");
}

void AlertsTab::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    
    QScrollArea *scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    
    QWidget *contentWidget = new QWidget();
    QVBoxLayout *contentLayout = new QVBoxLayout(contentWidget);
    contentLayout->setSpacing(20);
    
    QLabel *titleLabel = new QLabel("Security Alerts");
    titleLabel->setStyleSheet("font-size: 24px; font-weight: bold; color: #4a90d9;");
    contentLayout->addWidget(titleLabel);
    
    QHBoxLayout *headerLayout = new QHBoxLayout();
    alertCountLabel = new QLabel("Total Alerts: 0");
    alertCountLabel->setStyleSheet("font-size: 14px; color: #888888;");
    
    QPushButton *clearBtn = new QPushButton("Clear All");
    connect(clearBtn, &QPushButton::clicked, this, &AlertsTab::clearAlerts);
    
    QPushButton *exportBtn = new QPushButton("Export Logs");
    connect(exportBtn, &QPushButton::clicked, this, &AlertsTab::exportAlerts);
    
    headerLayout->addWidget(alertCountLabel);
    headerLayout->addStretch();
    headerLayout->addWidget(exportBtn);
    headerLayout->addWidget(clearBtn);
    contentLayout->addLayout(headerLayout);
    
    QSplitter *splitter = new QSplitter(Qt::Vertical);
    
    QGroupBox *listGroup = new QGroupBox("Alert History");
    QVBoxLayout *listLayout = new QVBoxLayout(listGroup);
    alertsList = new QListWidget();
    connect(alertsList, &QListWidget::currentRowChanged, this, &AlertsTab::showAlertDetails);
    listLayout->addWidget(alertsList);
    
    QGroupBox *detailsGroup = new QGroupBox("Alert Details");
    QVBoxLayout *detailsLayout = new QVBoxLayout(detailsGroup);
    alertDetailsText = new QTextEdit();
    alertDetailsText->setReadOnly(true);
    alertDetailsText->setPlaceholderText("Select an alert to view details...");
    detailsLayout->addWidget(alertDetailsText);
    
    splitter->addWidget(listGroup);
    splitter->addWidget(detailsGroup);
    splitter->setSizes({400, 200});
    
    contentLayout->addWidget(splitter);
    
    scrollArea->setWidget(contentWidget);
    mainLayout->addWidget(scrollArea);
}

void AlertsTab::addAlert(const QString& type, const QString& message, const QString& severity) {
    Alert alert;
    alert.type = type;
    alert.message = message;
    alert.severity = severity;
    alert.timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
    
    alerts.prepend(alert);
    
    QString icon;
    QString color;
    if (severity == "critical") {
        icon = "[!]";
        color = "#e74c3c";
    } else if (severity == "warning") {
        icon = "[!]";
        color = "#f39c12";
    } else {
        icon = "[i]";
        color = "#3498db";
    }
    
    QListWidgetItem *item = new QListWidgetItem(
        QString("%1 %2 [%3] %4").arg(icon, alert.timestamp, type, message));
    item->setForeground(QColor(color));
    alertsList->insertItem(0, item);
    
    alertCountLabel->setText(QString("Total Alerts: %1").arg(alerts.size()));
}

void AlertsTab::clearAlerts() {
    if (QMessageBox::question(this, "Clear Alerts", 
        "Are you sure you want to clear all alerts?") == QMessageBox::Yes) {
        alerts.clear();
        alertsList->clear();
        alertDetailsText->clear();
        alertCountLabel->setText("Total Alerts: 0");
        Logger::getInstance().log(Logger::INFO, "All alerts cleared");
    }
}

void AlertsTab::showAlertDetails() {
    int row = alertsList->currentRow();
    if (row < 0 || row >= alerts.size()) return;
    
    const Alert& alert = alerts[row];
    
    QString details;
    details += QString("Type: %1\n").arg(alert.type);
    details += QString("Severity: %1\n").arg(alert.severity.toUpper());
    details += QString("Timestamp: %1\n\n").arg(alert.timestamp);
    details += QString("Message:\n%1\n").arg(alert.message);
    
    alertDetailsText->setText(details);
}

void AlertsTab::exportAlerts() {
    QString filename = QFileDialog::getSaveFileName(this, "Export Alerts",
        "guardme_alerts.log", "Log Files (*.log);;Text Files (*.txt)");
    
    if (filename.isEmpty()) return;
    
    QFile file(filename);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << "GuardME Security Alerts Export\n";
        out << "Generated: " << QDateTime::currentDateTime().toString() << "\n";
        out << "========================================\n\n";
        
        for (const Alert& alert : alerts) {
            out << QString("[%1] [%2] [%3]\n%4\n\n")
                .arg(alert.timestamp, alert.severity.toUpper(), alert.type, alert.message);
        }
        
        file.close();
        QMessageBox::information(this, "Export Complete", 
            QString("Alerts exported to:\n%1").arg(filename));
    }
}
