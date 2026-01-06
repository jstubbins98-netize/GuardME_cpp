#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTabWidget>
#include <QStatusBar>
#include <QLabel>
#include <QTimer>
#include <QSystemTrayIcon>
#include <QMenu>

class DashboardTab;
class ControlsTab;
class ToolsTab;
class EmailProtectionTab;
class AlertsTab;
class ApiStatusTab;
class ChatbotWidget;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void updateStatusBar();
    void showAbout();
    void toggleMinimizeToTray();
    void trayIconActivated(QSystemTrayIcon::ActivationReason reason);
    void checkClamAVReminder();

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    void setupUI();
    void setupMenuBar();
    void setupSystemTray();
    void setupTabs();
    void applyStyles();
    
    QTabWidget *tabWidget;
    DashboardTab *dashboardTab;
    ControlsTab *controlsTab;
    ToolsTab *toolsTab;
    EmailProtectionTab *emailProtectionTab;
    AlertsTab *alertsTab;
    ApiStatusTab *apiStatusTab;
    ChatbotWidget *chatbotWidget;
    
    QLabel *statusLabel;
    QLabel *timeLabel;
    QTimer *statusTimer;
    
    QSystemTrayIcon *trayIcon;
    QMenu *trayMenu;
    bool minimizeToTray;
    
    QTimer *clamavReminderTimer;
    void showClamAVReminderNotification();
};

#endif
