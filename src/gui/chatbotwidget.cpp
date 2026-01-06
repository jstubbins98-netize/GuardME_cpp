#include "gui/chatbotwidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollBar>
#include <QScrollArea>
#include <QDateTime>
#include <QFile>
#include <QPixmap>
#include <QFrame>
#include <QProcess>
#include <QMessageBox>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

ChatbotWidget::ChatbotWidget(QWidget *parent) : QWidget(parent), speakEnabled(false) {
    loadResponses();
    setupUI();
}

void ChatbotWidget::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    
    toggleBtn = new QPushButton("Guardi's Help Desk");
    toggleBtn->setStyleSheet(R"(
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
    )");
    connect(toggleBtn, &QPushButton::clicked, this, &ChatbotWidget::toggleVisibility);
    
    chatContainer = new QWidget();
    chatContainer->setVisible(false);
    chatContainer->setStyleSheet(R"(
        QWidget {
            background-color: #2b2b2b;
            border: 1px solid #3c3c3c;
            border-radius: 8px;
        }
    )");
    chatContainer->setMinimumHeight(350);
    chatContainer->setMaximumHeight(500);
    
    QVBoxLayout *containerLayout = new QVBoxLayout(chatContainer);
    containerLayout->setContentsMargins(0, 0, 0, 0);
    
    QScrollArea *scrollArea = new QScrollArea();
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    scrollArea->setStyleSheet("QScrollArea { background: transparent; border: none; }");
    
    QWidget *contentWidget = new QWidget();
    contentWidget->setStyleSheet("background: transparent;");
    QVBoxLayout *chatLayout = new QVBoxLayout(contentWidget);
    
    QHBoxLayout *headerLayout = new QHBoxLayout();
    
    mascotLabel = new QLabel();
    setMascotExpression(Cartoon);
    mascotLabel->setFixedSize(52, 52);
    mascotLabel->setStyleSheet("background: transparent; border: none;");
    
    QLabel *headerLabel = new QLabel("Guardi's Help Desk");
    headerLabel->setStyleSheet("font-weight: bold; color: #4a90d9; padding: 5px; font-size: 14px;");
    
    speakCheckbox = new QCheckBox("Speak responses");
    speakCheckbox->setStyleSheet("QCheckBox { color: #ffffff; background: transparent; border: none; }");
    speakCheckbox->setChecked(false);
    connect(speakCheckbox, &QCheckBox::toggled, this, &ChatbotWidget::onSpeakToggled);
    
    headerLayout->addWidget(mascotLabel);
    headerLayout->addWidget(headerLabel);
    headerLayout->addStretch();
    headerLayout->addWidget(speakCheckbox);
    
    chatHistory = new QTextEdit();
    chatHistory->setReadOnly(true);
    chatHistory->setStyleSheet(R"(
        QTextEdit {
            background-color: #1e1e1e;
            border: none;
            border-radius: 4px;
        }
    )");
    
    QHBoxLayout *inputLayout = new QHBoxLayout();
    inputEdit = new QLineEdit();
    inputEdit->setPlaceholderText("Ask Guardi a question...");
    connect(inputEdit, &QLineEdit::returnPressed, this, &ChatbotWidget::sendMessage);
    
    QPushButton *sendBtn = new QPushButton("Send");
    connect(sendBtn, &QPushButton::clicked, this, &ChatbotWidget::sendMessage);
    
    inputLayout->addWidget(inputEdit);
    inputLayout->addWidget(sendBtn);
    
    chatLayout->addLayout(headerLayout);
    chatLayout->addWidget(chatHistory);
    chatLayout->addLayout(inputLayout);
    
    scrollArea->setWidget(contentWidget);
    containerLayout->addWidget(scrollArea);
    
    mainLayout->addWidget(toggleBtn);
    mainLayout->addWidget(chatContainer);
    
    addMessage("Guardi", "Hello! I'm Guardi, your security assistant. How can I help you today?", false);
}

void ChatbotWidget::setMascotExpression(Expression expr) {
    QString imagePath;
    switch (expr) {
        case Happy:
            imagePath = "resources/images/guardi_happy.png";
            break;
        case Cartoon:
        default:
            imagePath = "resources/images/guardi_cartoon.png";
            break;
    }
    
    QPixmap mascotPixmap(imagePath);
    if (mascotPixmap.isNull()) {
        mascotPixmap.load(":/images/" + imagePath.section('/', -1));
    }
    if (!mascotPixmap.isNull()) {
        mascotLabel->setPixmap(mascotPixmap.scaled(48, 48, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    }
}

void ChatbotWidget::loadResponses() {
    responses["url"] = "To check a URL for threats, go to the Tools tab and enter the URL in the URL Analysis section. I'll analyze it for malware, phishing, and other threats.";
    responses["virus"] = "You can scan files for viruses in the Tools tab. Select a file or folder and click 'Start Scan'. Make sure ClamAV is installed and running.";
    responses["password"] = "To check if your password has been compromised, go to Tools tab and use the Password Breach Check feature. Your password is hashed locally before being checked.";
    responses["email"] = "Check if your email has been in a data breach using the Email Breach Check in the Tools tab. You can also set up email protection in the Email Protection tab.";
    responses["download"] = "The Download Monitor watches your downloads folder for new files and automatically scans them. You can configure it in the Controls tab.";
    responses["whitelist"] = "You can whitelist trusted domains in the Tools tab. Whitelisted domains won't trigger security warnings.";
    responses["help"] = "I can help you with: URL scanning, virus detection, password/email breach checks, download monitoring, and general security questions. Just ask!";
    responses["safe"] = "To stay safe online: use strong unique passwords, enable 2FA, keep software updated, be cautious of suspicious links, and regularly scan for malware.";
    responses["thank"] = "You're welcome! I'm always here to help keep you safe online. Is there anything else you'd like to know?";
    responses["great"] = "I'm glad I could help! Let me know if you have any other security questions.";
    responses["awesome"] = "Happy to help! Stay safe out there, and don't hesitate to ask if you need anything.";
    
    responseExpressions["url"] = Cartoon;
    responseExpressions["virus"] = Cartoon;
    responseExpressions["password"] = Cartoon;
    responseExpressions["email"] = Cartoon;
    responseExpressions["download"] = Cartoon;
    responseExpressions["whitelist"] = Happy;
    responseExpressions["help"] = Happy;
    responseExpressions["safe"] = Cartoon;
    responseExpressions["thank"] = Happy;
    responseExpressions["great"] = Happy;
    responseExpressions["awesome"] = Happy;
    
    greetings << "hello" << "hi" << "hey" << "greetings";
    
    warningKeywords << "malware" << "breach" << "hack" << "attack" << "threat" 
                    << "danger" << "risk" << "vulnerable" << "compromised" << "infected"
                    << "phishing" << "scam" << "ransomware" << "trojan" << "spyware";
    
    defaultResponse = "I'm not sure about that. Try asking about: URL scanning, virus detection, password checks, email breaches, or download monitoring. Type 'help' for more info.";
}

QString ChatbotWidget::getResponse(const QString& input, Expression& expression) {
    QString lower = input.toLower().trimmed();
    
    for (const QString& greeting : greetings) {
        if (lower.contains(greeting)) {
            expression = Happy;
            return "Hello! How can I help you with your security today?";
        }
    }
    
    for (const QString& warning : warningKeywords) {
        if (lower.contains(warning)) {
            expression = Cartoon;
            break;
        }
    }
    
    for (auto it = responses.begin(); it != responses.end(); ++it) {
        if (lower.contains(it.key())) {
            if (responseExpressions.contains(it.key())) {
                expression = responseExpressions[it.key()];
            }
            return it.value();
        }
    }
    
    expression = Cartoon;
    return defaultResponse;
}

void ChatbotWidget::addMessage(const QString& sender, const QString& message, bool isUser) {
    QString color = isUser ? "#4a90d9" : "#2ecc71";
    QString timestamp = QDateTime::currentDateTime().toString("hh:mm");
    
    QString html = QString(
        "<div style='margin: 5px 0;'>"
        "<span style='color: %1; font-weight: bold;'>%2</span> "
        "<span style='color: #666666; font-size: 10px;'>%3</span><br>"
        "<span style='color: #ffffff;'>%4</span>"
        "</div>"
    ).arg(color, sender, timestamp, message);
    
    chatHistory->append(html);
    
    QScrollBar *bar = chatHistory->verticalScrollBar();
    bar->setValue(bar->maximum());
}

void ChatbotWidget::sendMessage() {
    QString message = inputEdit->text().trimmed();
    if (message.isEmpty()) return;
    
    addMessage("You", message, true);
    inputEdit->clear();
    
    Expression expr = Cartoon;
    QString response = getResponse(message, expr);
    setMascotExpression(expr);
    addMessage("Guardi", response, false);
    
    if (speakEnabled) {
        speakText(response);
    }
}

void ChatbotWidget::toggleVisibility() {
    chatContainer->setVisible(!chatContainer->isVisible());
    toggleBtn->setText(chatContainer->isVisible() ? "Hide Help Desk" : "Guardi's Help Desk");
    if (chatContainer->isVisible()) {
        setMascotExpression(Cartoon);
    }
}

void ChatbotWidget::onSpeakToggled(bool enabled) {
    if (enabled) {
        #ifndef Q_OS_MAC
        QProcess checkProcess;
        checkProcess.start("which", QStringList() << "espeak");
        checkProcess.waitForFinished(3000);
        if (checkProcess.exitCode() != 0) {
            QMessageBox::warning(this, "espeak Not Installed",
                "Text-to-speech requires espeak, which is not installed.\n\n"
                "To enable this feature:\n"
                "1. Delete the current binary (build/GuardME)\n"
                "2. Run ./setup.sh and select 'Yes' when asked to install espeak\n"
                "3. Recompile the application\n\n"
                "The speak option will be disabled.");
            speakCheckbox->setChecked(false);
            speakEnabled = false;
            return;
        }
        #endif
    }
    speakEnabled = enabled;
}

void ChatbotWidget::speakText(const QString& text) {
    QProcess *process = new QProcess(this);
    connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            process, &QProcess::deleteLater);
    
    QString cleanText = text;
    cleanText.replace("'", "");
    cleanText.replace("\"", "");
    cleanText.replace("\n", " ");
    
    #ifdef Q_OS_MAC
    process->start("say", QStringList() << cleanText);
    #else
    process->start("espeak", QStringList() << "-s" << "150" << cleanText);
    #endif
}
