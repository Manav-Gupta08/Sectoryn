#include "ui/ReportView.hpp"

#include "reports/HtmlReport.hpp"
#include "reports/JsonReport.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QLabel>
#include <QLocale>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSaveFile>
#include <QStackedWidget>
#include <QStandardPaths>
#include <QTextBrowser>
#include <QTextDocument>
#include <QUrl>
#include <QVBoxLayout>

#include <string>

namespace sectoryn::ui {

namespace {

// Larger reports are still saved in full, but laying them out in a widget would stall the UI.
constexpr qsizetype kMaxPreviewBytes = 4 * 1024 * 1024;

QByteArray toBytes(const std::string& text) {
    return QByteArray(text.data(), static_cast<qsizetype>(text.size()));
}

} // namespace

ReportView::ReportView(QWidget* parent)
    : AnalysisPanel(parent)
    , format_(new QComboBox(this))
    , includeStrings_(new QCheckBox(tr("Include &strings"), this))
    , includePath_(new QCheckBox(tr("Include full &path"), this))
    , preview_(new QStackedWidget(this))
    , html_(new QTextBrowser(this))
    , json_(new QPlainTextEdit(this))
    , note_(new QLabel(this)) {
    format_->addItem(tr("HTML report"));
    format_->addItem(tr("JSON report"));
    format_->setAccessibleName(tr("Report format"));
    includeStrings_->setToolTip(tr("Adds every extracted string. Indicators found in strings "
                                   "are always included."));
    includePath_->setToolTip(tr("Writes the full path instead of only the file name. Paths can "
                                "reveal user and folder names."));
    auto* saveButton = new QPushButton(tr("&Save Report..."), this);

    // Reports contain only in-page links. Other URLs are ignored rather than followed.
    html_->setOpenLinks(false);
    html_->setAccessibleName(tr("HTML report preview"));
    // Qt does not understand the report's CSS variables, so links would keep their default
    // dark blue, which is unreadable on the dark theme.
    html_->document()->setDefaultStyleSheet(QStringLiteral("a { color: #4cc2d6; }"));
    connect(html_, &QTextBrowser::anchorClicked, this, [this](const QUrl& url) {
        if (url.isRelative() && url.path().isEmpty() && url.hasFragment()) {
            html_->scrollToAnchor(url.fragment());
        }
    });

    json_->setReadOnly(true);
    json_->setLineWrapMode(QPlainTextEdit::NoWrap);
    json_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    json_->setAccessibleName(tr("JSON report preview"));

    preview_->addWidget(html_);
    preview_->addWidget(json_);

    note_->setTextFormat(Qt::PlainText);
    note_->setObjectName(QStringLiteral("mutedText"));
    note_->setWordWrap(true);

    connect(format_, &QComboBox::currentIndexChanged, this, &ReportView::refresh);
    connect(includeStrings_, &QCheckBox::toggled, this, &ReportView::refresh);
    connect(includePath_, &QCheckBox::toggled, this, &ReportView::refresh);
    connect(saveButton, &QPushButton::clicked, this, &ReportView::save);

    auto* controls = new QHBoxLayout;
    controls->addWidget(format_);
    controls->addWidget(includeStrings_);
    controls->addWidget(includePath_);
    controls->addStretch();
    controls->addWidget(saveButton);

    auto* content = new QWidget(this);
    auto* layout = new QVBoxLayout(content);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addLayout(controls);
    layout->addWidget(preview_, 1);
    layout->addWidget(note_);
    setContent(content);
    clear();
}

void ReportView::clear() {
    result_.reset();
    stale_ = false;
    html_->clear();
    json_->clear();
    showMessage(tr("Open a file to create a report."));
}

void ReportView::showResult(const SharedResult& result) {
    result_ = result;
    stale_ = true;
    if (isVisible()) {
        refresh();
    }
    showContent();
}

void ReportView::showEvent(QShowEvent* event) {
    AnalysisPanel::showEvent(event);
    if (stale_) {
        refresh();
    }
}

bool ReportView::htmlSelected() const {
    return format_->currentIndex() == 0;
}

ReportOptions ReportView::options() const {
    ReportOptions options;
    options.includeStrings = includeStrings_->isChecked();
    options.includeFilePath = includePath_->isChecked();
    return options;
}

QByteArray ReportView::render() const {
    return toBytes(htmlSelected() ? renderHtmlReport(*result_, options())
                                  : renderJsonReport(*result_, options()));
}

void ReportView::refresh() {
    if (!result_) {
        return;
    }
    if (!isVisible()) {
        stale_ = true;
        return;
    }
    stale_ = false;
    const QByteArray report = render();
    const bool html = htmlSelected();
    preview_->setCurrentIndex(html ? 0 : 1);
    if (report.size() > kMaxPreviewBytes) {
        html_->clear();
        json_->clear();
        note_->setText(tr("This report is %1 and too large to preview. Save it and open it in "
                          "a browser or text editor.")
                           .arg(QLocale::system().formattedDataSize(report.size())));
        return;
    }
    if (html) {
        html_->setHtml(QString::fromUtf8(report));
        note_->setText(tr("The preview is simplified. Saved reports are single files with no "
                          "scripts or external references; open them in any browser."));
    } else {
        json_->setPlainText(QString::fromUtf8(report));
        note_->setText(tr("The JSON layout is described in docs/report-format.md."));
    }
}

void ReportView::save() {
    if (!result_) {
        return;
    }
    const bool html = htmlSelected();
    const QString name = QFileInfo(QString::fromStdU16String(result_->file.path.u16string()))
                             .fileName();
    const QString suggested =
        QDir(QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation))
            .filePath(name + (html ? QStringLiteral(".report.html")
                                   : QStringLiteral(".report.json")));
    const QString path = QFileDialog::getSaveFileName(
        this, tr("Save Report"), suggested,
        html ? tr("HTML files (*.html);;All files (*)") : tr("JSON files (*.json);;All files (*)"));
    if (path.isEmpty()) {
        return;
    }

    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, tr("Save failed"), file.errorString());
        return;
    }
    const QByteArray report = render();
    if (file.write(report) != report.size() || !file.commit()) {
        QMessageBox::warning(this, tr("Save failed"), file.errorString());
    }
}

} // namespace sectoryn::ui
