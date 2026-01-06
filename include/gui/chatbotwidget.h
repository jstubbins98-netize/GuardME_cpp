#ifndef CHATBOTWIDGET_H
#define CHATBOTWIDGET_H

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QLabel>
#include <QCheckBox>
#include <QMap>
#include <QStringList>
#include <QProcess>

class ChatbotWidget : public QWidget {
    Q_OBJECT

public:
    explicit ChatbotWidget(QWidget *parent = nullptr);
    
    enum Expression {
        Cartoon,
        Happy
    };

private slots:
    void sendMessage();
    void toggleVisibility();
    void onSpeakToggled(bool enabled);

private:
    void setupUI();
    void loadResponses();
    QString getResponse(const QString& input, Expression& expression);
    void addMessage(const QString& sender, const QString& message, bool isUser);
    void setMascotExpression(Expression expr);
    void speakText(const QString& text);
    
    QPushButton *toggleBtn;
    QWidget *chatContainer;
    QTextEdit *chatHistory;
    QLineEdit *inputEdit;
    QLabel *mascotLabel;
    QCheckBox *speakCheckbox;
    bool speakEnabled;
    
    QMap<QString, QString> responses;
    QMap<QString, Expression> responseExpressions;
    QStringList greetings;
    QStringList warningKeywords;
    QString defaultResponse;
};

#endif
