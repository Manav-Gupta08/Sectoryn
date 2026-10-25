#include "ui/DashboardView.hpp"

#include "ui/Formatting.hpp"

#include <QDragEnterEvent>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QMimeData>
#include <QPushButton>
#include <QStyle>
#include <QUrl>
#include <QVBoxLayout>

#include <ranges>

namespace sectoryn::ui {

namespace {

QLabel* heading(const QString& text, QWidget* parent) {
    auto* label = new QLabel(text, parent);
    label->setObjectName(QStringLiteral("sectionHeading"));
    return label;
}

} // namespace

QStringList localFiles(const QMimeData* mime) {
    QStringList files;
    if (mime == nullptr || !mime->hasUrls()) {
        return files;
    }
    for (const QUrl& url : mime->urls()) {
        if (url.isLocalFile()) {
            files.append(url.toLocalFile());
        }
    }
    return files;
}

DashboardView::DashboardView(QWidget* parent)
    : QWidget(parent)
    , dropZone_(new QFrame(this))
    , summary_(new QLabel(this))
    , services_(new QLabel(this))
    , recent_(new QListWidget(this)) {
    setAcceptDrops(true);

    dropZone_->setObjectName(QStringLiteral("dropZone"));
    dropZone_->setMinimumHeight(180);
    auto* dropLayout = new QVBoxLayout(dropZone_);
    auto* dropTitle = new QLabel(tr("Drop a Windows executable here"), dropZone_);
    dropTitle->setAlignment(Qt::AlignCenter);
    dropTitle->setStyleSheet(QStringLiteral("font-size: 14pt;"));
    auto* dropHint = new QLabel(tr("Files are inspected locally and are never executed."),
                                dropZone_);
    dropHint->setObjectName(QStringLiteral("mutedText"));
    dropHint->setAlignment(Qt::AlignCenter);
    auto* openButton = new QPushButton(tr("&Open File..."), dropZone_);
    openButton->setObjectName(QStringLiteral("primaryButton"));
    openButton->setCursor(Qt::PointingHandCursor);
    connect(openButton, &QPushButton::clicked, this, &DashboardView::openRequested);

    dropLayout->addStretch();
    dropLayout->addWidget(dropTitle);
    dropLayout->addWidget(dropHint);
    dropLayout->addSpacing(8);
    dropLayout->addWidget(openButton, 0, Qt::AlignHCenter);
    dropLayout->addStretch();

    summary_->setTextFormat(Qt::PlainText);
    services_->setTextFormat(Qt::PlainText);
    services_->setObjectName(QStringLiteral("mutedText"));
    recent_->setAccessibleName(tr("Recent analyses"));
    connect(recent_, &QListWidget::itemActivated, this, [this](QListWidgetItem* item) {
        const auto index = static_cast<std::size_t>(recent_->row(item));
        if (index < results_.size()) {
            Q_EMIT resultActivated(results_[results_.size() - 1 - index]);
        }
    });

    auto* columns = new QHBoxLayout;
    auto* left = new QVBoxLayout;
    left->addWidget(heading(tr("This session"), this));
    left->addWidget(summary_);
    left->addSpacing(12);
    left->addWidget(heading(tr("Optional services"), this));
    left->addWidget(services_);
    left->addStretch();
    auto* right = new QVBoxLayout;
    right->addWidget(heading(tr("Recent analyses"), this));
    right->addWidget(recent_);
    columns->addLayout(left, 1);
    columns->addLayout(right, 2);

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(24, 24, 24, 24);
    layout->setSpacing(16);
    layout->addWidget(dropZone_);
    layout->addLayout(columns, 1);

    setServiceStatus({tr("No optional services are configured. All analysis runs offline.")});
    refreshSummary();
}

void DashboardView::addResult(const SharedResult& result) {
    if (!result) {
        return;
    }
    ++analyzedCount_;
    for (const Finding& finding : result->findings) {
        ++findingsBySeverity_[static_cast<std::size_t>(finding.severity)];
    }

    results_.push_back(result);
    if (results_.size() > kMaxRecent) {
        results_.erase(results_.begin());
    }

    recent_->clear();
    for (const SharedResult& shared : std::views::reverse(results_)) {
        const AnalysisResult& entry = *shared;
        const QString name = QFileInfo(QString::fromStdU16String(entry.file.path.u16string()))
                                 .fileName();
        auto* item = new QListWidgetItem(
            QStringLiteral("%1  -  %2").arg(name, toQString(toString(entry.risk.outcome))),
            recent_);
        item->setToolTip(QStringLiteral("SHA-256 %1").arg(toQString(entry.sha256)));
    }
    refreshSummary();
}

void DashboardView::setServiceStatus(const QStringList& lines) {
    services_->setText(lines.join(QLatin1Char('\n')));
}

void DashboardView::dragEnterEvent(QDragEnterEvent* event) {
    if (!localFiles(event->mimeData()).isEmpty()) {
        event->acceptProposedAction();
        setDragActive(true);
    }
}

void DashboardView::dragLeaveEvent(QDragLeaveEvent* event) {
    setDragActive(false);
    QWidget::dragLeaveEvent(event);
}

void DashboardView::dropEvent(QDropEvent* event) {
    setDragActive(false);
    const QStringList files = localFiles(event->mimeData());
    if (!files.isEmpty()) {
        event->acceptProposedAction();
        Q_EMIT filesDropped(files);
    }
}

void DashboardView::setDragActive(bool active) {
    dropZone_->setProperty("dragActive", active);
    dropZone_->style()->unpolish(dropZone_);
    dropZone_->style()->polish(dropZone_);
}

void DashboardView::refreshSummary() {
    if (analyzedCount_ == 0) {
        summary_->setText(tr("No files analyzed yet."));
        return;
    }
    QStringList lines{tr("Files analyzed: %1").arg(analyzedCount_)};
    for (int severity = static_cast<int>(Severity::Critical);
         severity >= static_cast<int>(Severity::Informational); --severity) {
        lines.append(tr("%1 findings: %2")
                         .arg(severityText(static_cast<Severity>(severity)))
                         .arg(findingsBySeverity_[static_cast<std::size_t>(severity)]));
    }
    summary_->setText(lines.join(QLatin1Char('\n')));
}

} // namespace sectoryn::ui
