#include <QApplication>
#include <QStyleFactory>
#include <QMessageBox>
#include <QIcon>
#include <iostream>
#include "gui/mainwindow.h"
#include "core/logger.h"
#include "core/configmanager.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    
    app.setApplicationName("GuardME");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("GuardME Security");
    
    QIcon appIcon(":/images/guardme_icon.png");
    if (appIcon.isNull()) {
        appIcon = QIcon("resources/images/guardme_icon.png");
    }
    app.setWindowIcon(appIcon);
    
    app.setStyle(QStyleFactory::create("Fusion"));
    
    QPalette darkPalette;
    darkPalette.setColor(QPalette::Window, QColor(53, 53, 53));
    darkPalette.setColor(QPalette::WindowText, Qt::white);
    darkPalette.setColor(QPalette::Base, QColor(25, 25, 25));
    darkPalette.setColor(QPalette::AlternateBase, QColor(53, 53, 53));
    darkPalette.setColor(QPalette::ToolTipBase, Qt::white);
    darkPalette.setColor(QPalette::ToolTipText, Qt::white);
    darkPalette.setColor(QPalette::Text, Qt::white);
    darkPalette.setColor(QPalette::Button, QColor(53, 53, 53));
    darkPalette.setColor(QPalette::ButtonText, Qt::white);
    darkPalette.setColor(QPalette::BrightText, Qt::red);
    darkPalette.setColor(QPalette::Link, QColor(42, 130, 218));
    darkPalette.setColor(QPalette::Highlight, QColor(42, 130, 218));
    darkPalette.setColor(QPalette::HighlightedText, Qt::black);
    app.setPalette(darkPalette);
    
    Logger::getInstance().log(Logger::INFO, "Initializing GuardME Security System...");
    
    ConfigManager::getInstance().loadConfig();
    
    MainWindow mainWindow;
    mainWindow.show();
    
    Logger::getInstance().log(Logger::INFO, "GuardME started successfully");
    
    return app.exec();
}
