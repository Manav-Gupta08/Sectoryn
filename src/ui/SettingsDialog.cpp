#include "ui/SettingsDialog.hpp"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <utility>

namespace sectoryn::ui {

namespace {

int clampToInt(std::uint64_t value) {
    constexpr auto kMax = static_cast<std::uint64_t>(std::numeric_limits<int>::max());
    return static_cast<int>(std::min(value, kMax));
}

int toMiB(std::uint64_t bytes) {
    return clampToInt(std::max<std::uint64_t>(1, (bytes + kMiB - 1) / kMiB));
}

QSpinBox* spinBox(QWidget* parent, std::uint64_t min, std::uint64_t max,
                  const QString& suffix = {}) {
    auto* box = new QSpinBox(parent);
    box->setRange(clampToInt(min), clampToInt(max));
    box->setSuffix(suffix);
    box->setGroupSeparatorShown(true);
    return box;
}

template <typename T>
T valueOf(const QSpinBox* box) {
    return static_cast<T>(box->value());
}

} // namespace

SettingsDialog::SettingsDialog(Config config, QWidget* parent)
    : QDialog(parent)
    , config_(std::move(config))
    , logLevel_(new QComboBox(this))
    , workers_(spinBox(this, 1, Config::kMaxWorkerCount))
    , queuedJobs_(spinBox(this, 1, Config::kMaxQueuedJobsCeiling))
    , maxFileMiB_(spinBox(this, 1, LimitCeilings::maxFileBytes / kMiB, QStringLiteral(" MiB")))
    , maxSections_(spinBox(this, 1, LimitCeilings::maxSections))
    , maxModules_(spinBox(this, 1, LimitCeilings::maxImportedModules))
    , maxFunctions_(spinBox(this, 1, LimitCeilings::maxImportedFunctions))
    , maxExports_(spinBox(this, 1, LimitCeilings::maxExports))
    , maxResources_(spinBox(this, 1, LimitCeilings::maxResourceEntries))
    , maxStrings_(spinBox(this, 1, LimitCeilings::maxStrings))
    , maxStringMiB_(
          spinBox(this, 1, LimitCeilings::maxStringBytes / kMiB, QStringLiteral(" MiB")))
    , minStringLength_(spinBox(this, 2, LimitCeilings::maxStringLength, tr(" characters")))
    , maxStringLength_(spinBox(this, 2, LimitCeilings::maxStringLength, tr(" characters")))
    , yaraFolder_(new QLineEdit(this))
    , error_(new QLabel(this)) {
    setWindowTitle(tr("Settings"));

    logLevel_->addItem(tr("Debug"), static_cast<int>(LogLevel::Debug));
    logLevel_->addItem(tr("Info"), static_cast<int>(LogLevel::Info));
    logLevel_->addItem(tr("Warning"), static_cast<int>(LogLevel::Warning));
    logLevel_->addItem(tr("Error"), static_cast<int>(LogLevel::Error));
    logLevel_->addItem(tr("Off"), static_cast<int>(LogLevel::Off));
    workers_->setToolTip(tr("Files analyzed at the same time during batch processing."));
    queuedJobs_->setToolTip(tr("Files that can wait in the batch queue. Larger batches are "
                               "refused rather than held in memory."));

    auto* general = new QGroupBox(tr("General"), this);
    auto* generalForm = new QFormLayout(general);
    generalForm->addRow(tr("&Log level:"), logLevel_);
    generalForm->addRow(tr("Batch &worker threads:"), workers_);
    generalForm->addRow(tr("Maximum &queued batch jobs:"), queuedJobs_);

    auto* limits = new QGroupBox(tr("Limits for each file"), this);
    auto* limitsForm = new QFormLayout(limits);
    limitsForm->addRow(tr("Maximum file &size:"), maxFileMiB_);
    limitsForm->addRow(tr("Maximum s&ections:"), maxSections_);
    limitsForm->addRow(tr("Maximum imported &modules:"), maxModules_);
    limitsForm->addRow(tr("Maximum imported &functions:"), maxFunctions_);
    limitsForm->addRow(tr("Maximum e&xports:"), maxExports_);
    limitsForm->addRow(tr("Maximum &resource entries:"), maxResources_);

    auto* strings = new QGroupBox(tr("String extraction"), this);
    auto* stringsForm = new QFormLayout(strings);
    stringsForm->addRow(tr("Maximum &number of strings:"), maxStrings_);
    stringsForm->addRow(tr("Maximum total &text:"), maxStringMiB_);
    stringsForm->addRow(tr("M&inimum length:"), minStringLength_);
    stringsForm->addRow(tr("Maximum len&gth:"), maxStringLength_);

    auto* yara = new QGroupBox(tr("YARA"), this);
    auto* yaraForm = new QFormLayout(yara);
    yaraFolder_->setPlaceholderText(tr("No folder: YARA scanning is off"));
    yaraFolder_->setClearButtonEnabled(true);
    yaraFolder_->setToolTip(tr("Every .yar and .yara file in this folder is compiled at "
                               "startup. Rules are never downloaded."));
    auto* browse = new QPushButton(tr("B&rowse..."), yara);
    connect(browse, &QPushButton::clicked, this, [this] {
        const QString folder = QFileDialog::getExistingDirectory(
            this, tr("YARA Rules Folder"), yaraFolder_->text());
        if (!folder.isEmpty()) {
            yaraFolder_->setText(folder);
        }
    });
    auto* folderRow = new QHBoxLayout;
    folderRow->addWidget(yaraFolder_, 1);
    folderRow->addWidget(browse);
    yaraForm->addRow(tr("Rules &folder:"), folderRow);

    auto* note = new QLabel(tr("Limits keep hostile files that declare huge structures from "
                               "exhausting memory or time. Changes apply to analyses started "
                               "after saving."),
                            this);
    note->setTextFormat(Qt::PlainText);
    note->setObjectName(QStringLiteral("mutedText"));
    note->setWordWrap(true);
    error_->setTextFormat(Qt::PlainText);
    error_->setObjectName(QStringLiteral("errorText"));
    error_->setWordWrap(true);
    error_->hide();

    auto* buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel | QDialogButtonBox::RestoreDefaults,
        this);
    connect(buttons, &QDialogButtonBox::accepted, this, &SettingsDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &SettingsDialog::reject);
    connect(buttons->button(QDialogButtonBox::RestoreDefaults), &QPushButton::clicked, this,
            [this] {
                config_ = Config{};
                load();
                error_->hide();
            });

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(general);
    layout->addWidget(limits);
    layout->addWidget(strings);
    layout->addWidget(yara);
    layout->addWidget(note);
    layout->addWidget(error_);
    layout->addWidget(buttons);
    load();
}

void SettingsDialog::load() {
    logLevel_->setCurrentIndex(logLevel_->findData(static_cast<int>(config_.logLevel)));
    workers_->setValue(clampToInt(config_.workerCount));
    queuedJobs_->setValue(clampToInt(config_.maxQueuedJobs));

    const AnalysisLimits& limits = config_.limits;
    loadedFileMiB_ = toMiB(limits.maxFileBytes);
    loadedStringMiB_ = toMiB(limits.maxStringBytes);
    maxFileMiB_->setValue(loadedFileMiB_);
    maxSections_->setValue(clampToInt(limits.maxSections));
    maxModules_->setValue(clampToInt(limits.maxImportedModules));
    maxFunctions_->setValue(clampToInt(limits.maxImportedFunctions));
    maxExports_->setValue(clampToInt(limits.maxExports));
    maxResources_->setValue(clampToInt(limits.maxResourceEntries));
    maxStrings_->setValue(clampToInt(limits.maxStrings));
    maxStringMiB_->setValue(loadedStringMiB_);
    minStringLength_->setValue(clampToInt(limits.minStringLength));
    maxStringLength_->setValue(clampToInt(limits.maxStringLength));
    yaraFolder_->setText(QString::fromStdU16String(config_.yaraRulesDirectory.u16string()));
}

Config SettingsDialog::collect() const {
    Config config = config_;
    config.logLevel = static_cast<LogLevel>(logLevel_->currentData().toInt());
    config.workerCount = valueOf<std::size_t>(workers_);
    config.maxQueuedJobs = valueOf<std::size_t>(queuedJobs_);

    AnalysisLimits& limits = config.limits;
    if (maxFileMiB_->value() != loadedFileMiB_) {
        limits.maxFileBytes = valueOf<std::uint64_t>(maxFileMiB_) * kMiB;
    }
    if (maxStringMiB_->value() != loadedStringMiB_) {
        limits.maxStringBytes = valueOf<std::size_t>(maxStringMiB_) * kMiB;
    }
    limits.maxSections = valueOf<std::size_t>(maxSections_);
    limits.maxImportedModules = valueOf<std::size_t>(maxModules_);
    limits.maxImportedFunctions = valueOf<std::size_t>(maxFunctions_);
    limits.maxExports = valueOf<std::size_t>(maxExports_);
    limits.maxResourceEntries = valueOf<std::size_t>(maxResources_);
    limits.maxStrings = valueOf<std::size_t>(maxStrings_);
    limits.minStringLength = valueOf<std::size_t>(minStringLength_);
    limits.maxStringLength = valueOf<std::size_t>(maxStringLength_);
    config.yaraRulesDirectory =
        std::filesystem::path(yaraFolder_->text().trimmed().toStdU16String());
    return config;
}

void SettingsDialog::accept() {
    const Config edited = collect();
    if (const Status valid = validate(edited); !valid) {
        error_->setText(QString::fromStdString(valid.error().message));
        error_->show();
        return;
    }
    config_ = edited;
    QDialog::accept();
}

} // namespace sectoryn::ui
