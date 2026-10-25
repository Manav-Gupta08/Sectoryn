#include "ui/AnalysisPanel.hpp"

#include <QLabel>
#include <QStackedLayout>

namespace sectoryn::ui {

AnalysisPanel::AnalysisPanel(QWidget* parent)
    : QWidget(parent)
    , layout_(new QStackedLayout(this))
    , message_(new QLabel(this)) {
    message_->setObjectName(QStringLiteral("panelMessage"));
    message_->setAlignment(Qt::AlignCenter);
    message_->setWordWrap(true);
    message_->setTextFormat(Qt::PlainText);
    layout_->addWidget(message_);
}

bool AnalysisPanel::reveal(const Evidence&) {
    return false;
}

void AnalysisPanel::setContent(QWidget* content) {
    layout_->addWidget(content);
}

void AnalysisPanel::showContent() {
    if (layout_->count() > 1) {
        layout_->setCurrentIndex(1);
    }
}

void AnalysisPanel::showMessage(const QString& message) {
    message_->setText(message);
    layout_->setCurrentWidget(message_);
}

} // namespace sectoryn::ui
