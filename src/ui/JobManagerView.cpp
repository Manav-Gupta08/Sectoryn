#include "ui/JobManagerView.hpp"

#include "reports/BatchExporter.hpp"
#include "ui/DashboardView.hpp"
#include "ui/models/JobTableModel.hpp"
#include "utilities/FileIo.hpp"

#include <QCheckBox>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QMessageBox>
#include <QMetaObject>
#include <QPushButton>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <system_error>
#include <utility>

namespace sectoryn::ui {

namespace {

// Stops a folder scan from wandering through an entire drive.
constexpr std::size_t kMaxFolderEntries = 20000;

struct FolderScan {
    QStringList files;
    bool truncated = false;
};

// Regular files below `folder`. Symbolic links are skipped so a scan cannot leave the folder.
FolderScan scanFolder(const std::filesystem::path& folder) {
    namespace fs = std::filesystem;
    FolderScan scan;
    std::error_code error;
    fs::recursive_directory_iterator it(folder, fs::directory_options::skip_permission_denied,
                                        error);
    std::size_t visited = 0;
    for (; !error && it != fs::recursive_directory_iterator(); it.increment(error)) {
        if (++visited > kMaxFolderEntries) {
            scan.truncated = true;
            break;
        }
        std::error_code typeError;
        if (!it->is_symlink(typeError) && it->is_regular_file(typeError)) {
            scan.files.append(QString::fromStdU16String(it->path().u16string()));
        }
    }
    scan.files.sort();
    return scan;
}

} // namespace

JobManagerView::JobManagerView(std::shared_ptr<const AnalysisEngine> engine, BatchOptions options,
                               QWidget* parent)
    : QWidget(parent)
    , engine_(std::move(engine))
    , options_(options)
    , model_(new JobTableModel(this))
    , sorted_(new QSortFilterProxyModel(this))
    , table_(new QTableView(this))
    , summary_(new QLabel(this))
    , cancelSelected_(new QPushButton(tr("Cancel &Selected"), this))
    , cancelAll_(new QPushButton(tr("&Cancel All"), this))
    , saveReports_(new QCheckBox(tr("Save &reports to folder..."), this)) {
    setWindowTitle(tr("Batch Analysis"));
    setAcceptDrops(true);

    auto* addFilesButton = new QPushButton(tr("Add &Files..."), this);
    auto* addFolderButton = new QPushButton(tr("Add F&older..."), this);
    auto* clearButton = new QPushButton(tr("C&lear Finished"), this);
    auto* exportButton = new QPushButton(tr("&Export Summary..."), this);
    saveReports_->setToolTip(tr("Writes a JSON and an HTML report for every completed file, "
                                "named after its SHA-256."));
    connect(saveReports_, &QCheckBox::clicked, this, &JobManagerView::chooseReportFolder);
    connect(exportButton, &QPushButton::clicked, this, &JobManagerView::chooseSummaryFile);

    connect(addFilesButton, &QPushButton::clicked, this, [this] {
        const QStringList files =
            QFileDialog::getOpenFileNames(this, tr("Add Files to Batch"), lastDirectory_);
        if (!files.isEmpty()) {
            lastDirectory_ = QFileInfo(files.front()).absolutePath();
            addFiles(files);
        }
    });
    connect(addFolderButton, &QPushButton::clicked, this, [this] {
        const QString folder =
            QFileDialog::getExistingDirectory(this, tr("Add Folder to Batch"), lastDirectory_);
        if (!folder.isEmpty()) {
            lastDirectory_ = folder;
            addFolder(folder);
        }
    });
    connect(cancelSelected_, &QPushButton::clicked, this, &JobManagerView::cancelSelected);
    connect(cancelAll_, &QPushButton::clicked, this, &JobManagerView::cancelAll);
    connect(clearButton, &QPushButton::clicked, this, [this] {
        model_->removeFinished();
        updateSummary();
    });

    sorted_->setSourceModel(model_);
    sorted_->setSortRole(JobTableModel::SortRole);
    table_->setModel(sorted_);
    table_->setSortingEnabled(true);
    table_->sortByColumn(-1, Qt::AscendingOrder);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->setWordWrap(false);
    table_->verticalHeader()->hide();
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(JobTableModel::FileColumn,
                                                     QHeaderView::Stretch);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setAccessibleName(tr("Batch jobs"));
    connect(table_, &QTableView::doubleClicked, this,
            [this](const QModelIndex& index) { openJob(sorted_->mapToSource(index).row()); });

    summary_->setTextFormat(Qt::PlainText);
    summary_->setObjectName(QStringLiteral("mutedText"));
    summary_->setWordWrap(true);

    auto* controls = new QHBoxLayout;
    controls->addWidget(addFilesButton);
    controls->addWidget(addFolderButton);
    controls->addStretch();
    controls->addWidget(cancelSelected_);
    controls->addWidget(cancelAll_);
    controls->addWidget(clearButton);

    auto* output = new QHBoxLayout;
    output->addWidget(saveReports_);
    output->addStretch();
    output->addWidget(exportButton);

    auto* layout = new QVBoxLayout(this);
    layout->addLayout(controls);
    layout->addWidget(table_, 1);
    layout->addLayout(output);
    layout->addWidget(summary_);
    resize(900, 520);
    updateSummary();
}

JobManagerView::~JobManagerView() {
    // Updates still in flight are queued to this object and are dropped along with it.
    manager_.reset();
}

void JobManagerView::configure(std::shared_ptr<const AnalysisEngine> engine,
                               BatchOptions options) {
    engine_ = std::move(engine);
    options_ = options;
    reconfigure_ = true;
}

bool JobManagerView::ensureManager() {
    if (manager_ && reconfigure_ && manager_->activeCount() == 0) {
        manager_.reset();
    }
    if (manager_) {
        return true;
    }
    Result<std::unique_ptr<BatchManager>> created =
        BatchManager::create(engine_, options_, [this](const JobUpdate& update) {
            QMetaObject::invokeMethod(
                this, [this, update] { apply(update); }, Qt::QueuedConnection);
        });
    if (!created) {
        QMessageBox::warning(this, tr("Batch analysis unavailable"),
                             QString::fromStdString(created.error().describe()));
        return false;
    }
    manager_ = std::move(created).value();
    reconfigure_ = false;
    return true;
}

void JobManagerView::apply(const JobUpdate& update) {
    model_->apply(update);
    if (update.result) {
        if (!reportFolder_.isEmpty()) {
            constexpr std::array kFormats = {ReportFormat::Json, ReportFormat::Html};
            const std::filesystem::path folder(reportFolder_.toStdU16String());
            if (const auto written = writeReports(folder, *update.result, kFormats); !written) {
                notice_ = tr("Reports could not be saved: %1.")
                              .arg(QString::fromStdString(written.error().message));
            }
        }
        Q_EMIT jobCompleted(update.result);
    }
    updateSummary();
}

void JobManagerView::setReportFolder(const QString& folder) {
    reportFolder_ = folder;
    saveReports_->setChecked(!folder.isEmpty());
    updateSummary();
}

void JobManagerView::chooseReportFolder(bool enabled) {
    QString folder;
    if (enabled) {
        folder = QFileDialog::getExistingDirectory(this, tr("Save Reports To"), lastDirectory_);
    }
    setReportFolder(folder);
}

Status JobManagerView::exportSummary(const QString& path) const {
    std::vector<BatchEntry> entries;
    entries.reserve(model_->jobs().size());
    for (const JobRow& job : model_->jobs()) {
        entries.push_back({.id = job.id,
                           .path = std::filesystem::path(job.path.toStdU16String()),
                           .state = job.state,
                           .sha256 = job.sha256,
                           .outcome = job.outcome,
                           .score = job.score,
                           .findings = job.findings,
                           .duplicateOf = job.duplicateOf,
                           .message = job.message.toStdString()});
    }
    const bool json = path.endsWith(QStringLiteral(".json"), Qt::CaseInsensitive);
    return writeFileAtomically(std::filesystem::path(path.toStdU16String()),
                               json ? renderBatchJson(entries) : renderBatchCsv(entries));
}

void JobManagerView::chooseSummaryFile() {
    const QString path =
        QFileDialog::getSaveFileName(this, tr("Export Batch Summary"), lastDirectory_,
                                     tr("CSV files (*.csv);;JSON files (*.json)"));
    if (path.isEmpty()) {
        return;
    }
    if (const Status saved = exportSummary(path); !saved) {
        QMessageBox::warning(this, tr("Export failed"),
                             QString::fromStdString(saved.error().describe()));
    }
}

int JobManagerView::addFiles(const QStringList& paths) {
    if (paths.isEmpty() || !ensureManager()) {
        return 0;
    }
    int queued = 0;
    QString refusal;
    for (const QString& path : paths) {
        const Result<JobId> id = manager_->submit(std::filesystem::path(path.toStdU16String()));
        if (!id) {
            refusal = QString::fromStdString(id.error().message);
            break;
        }
        ++queued;
    }
    const auto skipped = static_cast<int>(paths.size() - queued);
    notice_ = skipped == 0
                  ? QString()
                  : tr("%n file(s) were not added: %1.", nullptr, skipped).arg(refusal);
    updateSummary();
    return queued;
}

int JobManagerView::addFolder(const QString& folder) {
    const FolderScan scan = scanFolder(std::filesystem::path(folder.toStdU16String()));
    if (scan.files.isEmpty()) {
        notice_ = tr("No files were found in %1.").arg(folder);
        updateSummary();
        return 0;
    }
    const int queued = addFiles(scan.files);
    if (scan.truncated) {
        notice_ += tr(" The folder scan stopped after %1 entries.").arg(kMaxFolderEntries);
        notice_ = notice_.trimmed();
        updateSummary();
    }
    return queued;
}

void JobManagerView::cancelAll() {
    if (manager_) {
        manager_->cancelAll();
    }
}

void JobManagerView::cancelSelected() {
    if (!manager_) {
        return;
    }
    for (const QModelIndex& index : table_->selectionModel()->selectedRows()) {
        if (const JobRow* job = model_->jobAt(sorted_->mapToSource(index).row())) {
            manager_->cancel(job->id);
        }
    }
}

void JobManagerView::openJob(int row) {
    const JobRow* job = model_->jobAt(row);
    if (job == nullptr) {
        return;
    }
    if (job->result) {
        Q_EMIT resultActivated(job->result);
    } else if (job->state == JobState::Completed || job->state == JobState::Duplicate) {
        Q_EMIT reanalysisRequested(job->path);
    }
}

void JobManagerView::updateSummary() {
    const std::size_t active = model_->count(JobState::Queued) + model_->count(JobState::Running);
    QString text;
    if (model_->rowCount() == 0) {
        text = tr("Add files or a folder, or drop them here. Files are analyzed %n at a time.",
                  nullptr, static_cast<int>(options_.workerCount));
    } else {
        text = tr("%1 queued, %2 running, %3 completed, %4 duplicates, %5 failed, %6 cancelled.")
                   .arg(model_->count(JobState::Queued))
                   .arg(model_->count(JobState::Running))
                   .arg(model_->count(JobState::Completed))
                   .arg(model_->count(JobState::Duplicate))
                   .arg(model_->count(JobState::Failed))
                   .arg(model_->count(JobState::Cancelled));
    }
    if (!notice_.isEmpty()) {
        text += QLatin1Char(' ') + notice_;
    }
    if (!reportFolder_.isEmpty()) {
        text += QLatin1Char(' ') + tr("Reports are saved to %1.").arg(reportFolder_);
    }
    summary_->setText(text);
    cancelAll_->setEnabled(active > 0);
    cancelSelected_->setEnabled(active > 0);
}

void JobManagerView::dragEnterEvent(QDragEnterEvent* event) {
    if (!localFiles(event->mimeData()).isEmpty()) {
        event->acceptProposedAction();
    }
}

void JobManagerView::dropEvent(QDropEvent* event) {
    const QStringList paths = localFiles(event->mimeData());
    if (paths.isEmpty()) {
        return;
    }
    event->acceptProposedAction();
    QStringList files;
    for (const QString& path : paths) {
        if (QFileInfo(path).isDir()) {
            addFolder(path);
        } else {
            files.append(path);
        }
    }
    addFiles(files);
}

} // namespace sectoryn::ui
