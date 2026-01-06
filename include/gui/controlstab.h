#ifndef CONTROLSTAB_H
#define CONTROLSTAB_H

#include <QWidget>
#include <QCheckBox>
#include <QLineEdit>
#include <QPushButton>
#include <QListWidget>

class ControlsTab : public QWidget {
    Q_OBJECT

public:
    explicit ControlsTab(QWidget *parent = nullptr);

private slots:
    void toggleUrlMonitor(bool enabled);
    void toggleDownloadMonitor(bool enabled);
    void toggleVirusScanner(bool enabled);
    void browseDownloadsPath();
    void updateExcludedExtensions();

private:
    void setupUI();
    void loadSettings();
    
    QCheckBox *urlMonitorCheck;
    QCheckBox *downloadMonitorCheck;
    QCheckBox *virusScanCheck;
    QLineEdit *downloadsPathEdit;
    QLineEdit *excludedExtEdit;
    QListWidget *excludedList;
};

#endif
