#include "gui/mainwindow.h"
#include "gui/dashboardtab.h"
#include "gui/controlstab.h"
#include "gui/toolstab.h"
#include "gui/emailprotectiontab.h"
#include "gui/alertstab.h"
#include "gui/apistatustab.h"
#include "gui/chatbotwidget.h"
#include "core/logger.h"
#include <QMenuBar>
#include <QVBoxLayout>
#include <QMessageBox>
#include <QCloseEvent>
#include <QDateTime>
#include <QApplication>
#include <QFile>
#include <QSettings>

static const QString CLAMAV_REMINDER_KEY = "clamav/lastReminder";
static const int REMINDER_INTERVAL_DAYS = 7;
static const int REMINDER_CHECK_INTERVAL_MS = 3600000;

MainWindow::MainWindow(QWidget *parent) 
    : QMainWindow(parent), minimizeToTray(true) {
    
    setWindowTitle("GuardME - Advanced Cybersecurity Protection");
    setMinimumSize(1200, 800);
    resize(1400, 900);
    
    setupUI();
    setupMenuBar();
    setupSystemTray();
    setupTabs();
    applyStyles();
    
    statusTimer = new QTimer(this);
    connect(statusTimer, &QTimer::timeout, this, &MainWindow::updateStatusBar);
    statusTimer->start(1000);
    
    clamavReminderTimer = new QTimer(this);
    connect(clamavReminderTimer, &QTimer::timeout, this, &MainWindow::checkClamAVReminder);
    clamavReminderTimer->start(REMINDER_CHECK_INTERVAL_MS);
    
    QTimer::singleShot(3000, this, &MainWindow::checkClamAVReminder);
    
    Logger::getInstance().log(Logger::SUCCESS, "Main window initialized");
}

MainWindow::~MainWindow() {
    if (trayIcon) {
        trayIcon->hide();
    }
}

void MainWindow::setupUI() {
    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setContentsMargins(10, 10, 10, 10);
    
    tabWidget = new QTabWidget(this);
    tabWidget->setDocumentMode(true);
    mainLayout->addWidget(tabWidget);
    
    chatbotWidget = new ChatbotWidget(this);
    mainLayout->addWidget(chatbotWidget);
    
    setCentralWidget(centralWidget);
    
    statusLabel = new QLabel("GuardME Protection Active");
    timeLabel = new QLabel(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"));
    
    statusBar()->addWidget(statusLabel);
    statusBar()->addPermanentWidget(timeLabel);
}

void MainWindow::setupMenuBar() {
    QMenu *fileMenu = menuBar()->addMenu("&File");
    
    QAction *settingsAction = fileMenu->addAction("&Settings");
    connect(settingsAction, &QAction::triggered, [this]() {
        tabWidget->setCurrentIndex(1);
    });
    
    fileMenu->addSeparator();
    
    QAction *exitAction = fileMenu->addAction("E&xit");
    connect(exitAction, &QAction::triggered, [this]() {
        minimizeToTray = false;
        close();
    });
    
    QMenu *toolsMenu = menuBar()->addMenu("&Tools");
    
    QAction *scanAction = toolsMenu->addAction("&Quick Virus Scan");
    connect(scanAction, &QAction::triggered, [this]() {
        tabWidget->setCurrentIndex(2);
    });
    
    QAction *breachCheckAction = toolsMenu->addAction("&Breach Check");
    connect(breachCheckAction, &QAction::triggered, [this]() {
        tabWidget->setCurrentIndex(2);
    });
    
    QMenu *helpMenu = menuBar()->addMenu("&Help");
    
    QAction *aboutAction = helpMenu->addAction("&About GuardME");
    connect(aboutAction, &QAction::triggered, this, &MainWindow::showAbout);
    
    QAction *helpAction = helpMenu->addAction("&Help");
    connect(helpAction, &QAction::triggered, [this]() {
        chatbotWidget->setVisible(!chatbotWidget->isVisible());
    });
}

void MainWindow::setupSystemTray() {
    trayIcon = new QSystemTrayIcon(this);
    trayIcon->setToolTip("GuardME - Cybersecurity Protection");
    
    trayMenu = new QMenu(this);
    
    QAction *showAction = trayMenu->addAction("Show GuardME");
    connect(showAction, &QAction::triggered, [this]() {
        show();
        raise();
        activateWindow();
    });
    
    trayMenu->addSeparator();
    
    QAction *exitAction = trayMenu->addAction("Exit");
    connect(exitAction, &QAction::triggered, [this]() {
        minimizeToTray = false;
        close();
    });
    
    trayIcon->setContextMenu(trayMenu);
    connect(trayIcon, &QSystemTrayIcon::activated, this, &MainWindow::trayIconActivated);
    
    trayIcon->show();
}

void MainWindow::setupTabs() {
    dashboardTab = new DashboardTab(this);
    controlsTab = new ControlsTab(this);
    toolsTab = new ToolsTab(this);
    emailProtectionTab = new EmailProtectionTab(this);
    alertsTab = new AlertsTab(this);
    apiStatusTab = new ApiStatusTab(this);
    
    tabWidget->addTab(dashboardTab, "Dashboard");
    tabWidget->addTab(controlsTab, "Controls");
    tabWidget->addTab(toolsTab, "Tools");
    tabWidget->addTab(emailProtectionTab, "Email Protection");
    tabWidget->addTab(alertsTab, "Alerts");
    tabWidget->addTab(apiStatusTab, "API Status");
}

void MainWindow::applyStyles() {
    setStyleSheet(R"(
        QMainWindow {
            background-color: #2b2b2b;
        }
        QTabWidget::pane {
            border: 1px solid #3c3c3c;
            background-color: #2b2b2b;
            border-radius: 4px;
        }
        QTabBar::tab {
            background-color: #3c3c3c;
            color: #ffffff;
            padding: 10px 20px;
            margin-right: 2px;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
        }
        QTabBar::tab:selected {
            background-color: #4a90d9;
        }
        QTabBar::tab:hover:!selected {
            background-color: #4c4c4c;
        }
        QPushButton {
            background-color: #4a90d9;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #5a9fe9;
        }
        QPushButton:pressed {
            background-color: #3a80c9;
        }
        QPushButton:disabled {
            background-color: #555555;
            color: #888888;
        }
        QLineEdit, QTextEdit, QPlainTextEdit {
            background-color: #1e1e1e;
            color: #ffffff;
            border: 1px solid #3c3c3c;
            border-radius: 4px;
            padding: 6px;
        }
        QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
            border-color: #4a90d9;
        }
        QLabel {
            color: #ffffff;
        }
        QGroupBox {
            font-weight: bold;
            border: 1px solid #3c3c3c;
            border-radius: 4px;
            margin-top: 1em;
            padding-top: 10px;
            color: #ffffff;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px;
        }
        QListWidget {
            background-color: #1e1e1e;
            color: #ffffff;
            border: 1px solid #3c3c3c;
            border-radius: 4px;
        }
        QListWidget::item:selected {
            background-color: #4a90d9;
        }
        QCheckBox {
            color: #ffffff;
        }
        QCheckBox::indicator {
            width: 18px;
            height: 18px;
        }
        QProgressBar {
            border: 1px solid #3c3c3c;
            border-radius: 4px;
            text-align: center;
            color: white;
        }
        QProgressBar::chunk {
            background-color: #4a90d9;
            border-radius: 3px;
        }
        QScrollBar:vertical {
            background-color: #2b2b2b;
            width: 12px;
            border-radius: 6px;
        }
        QScrollBar::handle:vertical {
            background-color: #4c4c4c;
            border-radius: 6px;
            min-height: 20px;
        }
        QScrollBar::handle:vertical:hover {
            background-color: #5c5c5c;
        }
        QStatusBar {
            background-color: #1e1e1e;
            color: #ffffff;
        }
        QMenuBar {
            background-color: #2b2b2b;
            color: #ffffff;
        }
        QMenuBar::item:selected {
            background-color: #4a90d9;
        }
        QMenu {
            background-color: #2b2b2b;
            color: #ffffff;
            border: 1px solid #3c3c3c;
        }
        QMenu::item:selected {
            background-color: #4a90d9;
        }
    )");
}

void MainWindow::updateStatusBar() {
    timeLabel->setText(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"));
}

void MainWindow::showAbout() {
    QMessageBox::about(this, "About GuardME",
        "<h2>GuardME v1.0.0</h2>"
        "<p>Advanced Cybersecurity Protection Suite</p>"
        "<p>Features:</p>"
        "<ul>"
        "<li>Real-time URL threat detection</li>"
        "<li>Download monitoring and protection</li>"
        "<li>ClamAV virus scanning</li>"
        "<li>Email and password breach checking</li>"
        "<li>WHOIS and SSL analysis</li>"
        "<li>AI-powered threat assessment</li>"
        "</ul>"
        "<p>Built with Qt 6 and C++</p>");
}

void MainWindow::toggleMinimizeToTray() {
    minimizeToTray = !minimizeToTray;
}

void MainWindow::trayIconActivated(QSystemTrayIcon::ActivationReason reason) {
    if (reason == QSystemTrayIcon::DoubleClick) {
        if (isVisible()) {
            hide();
        } else {
            show();
            raise();
            activateWindow();
        }
    }
}

void MainWindow::closeEvent(QCloseEvent *event) {
    if (minimizeToTray && trayIcon->isVisible()) {
        hide();
        trayIcon->showMessage("GuardME", "Application minimized to tray. Double-click to restore.",
                              QSystemTrayIcon::Information, 2000);
        event->ignore();
    } else {
        event->accept();
    }
}

void MainWindow::checkClamAVReminder() {
    QSettings settings("GuardME", "GuardME");
    QDateTime lastReminder = settings.value(CLAMAV_REMINDER_KEY, QDateTime()).toDateTime();
    
    if (!lastReminder.isValid() || lastReminder.daysTo(QDateTime::currentDateTime()) >= REMINDER_INTERVAL_DAYS) {
        showClamAVReminderNotification();
        settings.setValue(CLAMAV_REMINDER_KEY, QDateTime::currentDateTime());
    }
}

void MainWindow::showClamAVReminderNotification() {
    if (trayIcon && trayIcon->isVisible()) {
        trayIcon->showMessage(
            "ClamAV Update Reminder",
            "Weekly reminder: Update your virus definitions!\nRun: sudo freshclam",
            QSystemTrayIcon::Warning,
            10000
        );
    }
    
    QMessageBox::information(
        this,
        "ClamAV Update Reminder",
        "<h3>Weekly Reminder</h3>"
        "<p>Keep your virus definitions up to date for best protection!</p>"
        "<p><b>Run:</b> <code>sudo freshclam</code></p>"
        "<p>This updates ClamAV's virus signature database.</p>"
    );
    
    Logger::getInstance().log(Logger::INFO, "ClamAV update reminder shown");
}
