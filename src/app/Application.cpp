#include "app/Application.hpp"

#include "core/Config.hpp"
#include "engine/AnalysisEngine.hpp"
#include "engine/signature/SignatureEnrichment.hpp"
#include "platform/ISignatureVerifier.hpp"
#include "ui/AnalysisController.hpp"
#include "ui/EntropyPanel.hpp"
#include "ui/ExportsView.hpp"
#include "ui/FindingsPanel.hpp"
#include "ui/HeadersView.hpp"
#include "ui/ImportsView.hpp"
#include "ui/JobManagerView.hpp"
#include "ui/MainWindow.hpp"
#include "ui/OverviewPanel.hpp"
#include "ui/ReportView.hpp"
#include "ui/ReputationView.hpp"
#include "ui/ResourcesView.hpp"
#include "ui/SectionsView.hpp"
#include "ui/SettingsDialog.hpp"
#include "ui/SignatureView.hpp"
#include "ui/StringsView.hpp"
#include "ui/YaraView.hpp"

#ifdef SECTORYN_HAVE_YARA
#include "detectors/yara/YaraCompiler.hpp"
#include "engine/yara/YaraEnrichment.hpp"
#endif

#include <QAction>
#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QKeySequence>
#include <QLocale>
#include <QMenu>
#include <QMessageBox>
#include <QSaveFile>
#include <QStandardPaths>
#include <QStatusBar>
#include <QTimer>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <format>
#include <iostream>
#include <string>
#include <vector>

#ifndef SECTORYN_VERSION
#error "SECTORYN_VERSION must be defined by the build system"
#endif

namespace sectoryn {

namespace {

constexpr std::uintmax_t kMaxLogFileBytes = 1024ULL * 1024ULL;

std::filesystem::path toPath(const QString& path) {
    return std::filesystem::path(path.toStdU16String());
}

// sectoryn.conf in the per-user configuration directory, or empty if there is none.
QString configFilePath() {
    const QString directory = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    return directory.isEmpty() ? QString()
                               : QDir(directory).filePath(QStringLiteral("sectoryn.conf"));
}

// A missing file means defaults; a broken one is reported and also falls back to defaults
// rather than refusing to start.
Config loadUserConfig(Logger& logger) {
    const QString file = configFilePath();
    if (file.isEmpty() || !QFile::exists(file)) {
        return {};
    }
    Result<Config> config = loadConfig(toPath(file));
    if (!config) {
        logger.warning("Ignoring configuration file: " + config.error().describe());
        return {};
    }
    logger.info("Loaded configuration file");
    return std::move(config).value();
}

Status saveUserConfig(const Config& config) {
    const QString file = configFilePath();
    if (file.isEmpty() || !QDir().mkpath(QFileInfo(file).absolutePath())) {
        return Error{ErrorCode::IoFailure, "no writable configuration directory"};
    }
    QSaveFile out(file);
    const std::string text = formatConfig(config);
    if (!out.open(QIODevice::WriteOnly) ||
        out.write(text.data(), static_cast<qint64>(text.size())) !=
            static_cast<qint64>(text.size()) ||
        !out.commit()) {
        return Error{ErrorCode::IoFailure, out.errorString().toStdString()};
    }
    return {};
}

BatchOptions batchOptions(const Config& config) {
    return {config.workerCount, config.maxQueuedJobs};
}

void applyStyleSheet(QApplication& app) {
    QFile style(QStringLiteral(":/styles/dark.qss"));
    if (style.open(QIODevice::ReadOnly | QIODevice::Text)) {
        app.setStyleSheet(QString::fromUtf8(style.readAll()));
    }
}

#ifdef SECTORYN_HAVE_YARA
using Enrichments = std::vector<std::shared_ptr<const IEnrichment>>;

QString toQString(const std::string& text) {
    return QString::fromStdString(text);
}

// The .yar and .yara files directly inside `directory`, sorted so that rule order is stable.
Result<std::vector<std::filesystem::path>> yaraRuleFiles(const std::filesystem::path& directory) {
    std::error_code error;
    std::filesystem::directory_iterator it(directory, error);
    if (error) {
        return Error{ErrorCode::IoFailure, error.message()};
    }
    std::vector<std::filesystem::path> files;
    for (const std::filesystem::directory_iterator end; it != end; it.increment(error)) {
        if (error) {
            return Error{ErrorCode::IoFailure, error.message()};
        }
        const std::filesystem::path extension = it->path().extension();
        if ((extension == ".yar" || extension == ".yara") && it->is_regular_file(error)) {
            if (files.size() == YaraLimits::kMaxSources) {
                return Error{ErrorCode::ResourceLimitExceeded,
                             std::format("more than {} rule files", YaraLimits::kMaxSources)};
            }
            files.push_back(it->path());
        }
    }
    std::ranges::sort(files);
    return files;
}

// Adds the YARA module when rules are configured and compile, and describes the outcome.
QString addYara(const Config& config, Enrichments& enrichments, Logger& logger) {
    const std::filesystem::path& directory = config.yaraRulesDirectory;
    if (directory.empty()) {
        return QObject::tr("No YARA rules folder is set. Choose one in Tools > Settings.");
    }
    const QString folder = QString::fromStdU16String(directory.u16string());
    const Result<std::vector<std::filesystem::path>> files = yaraRuleFiles(directory);
    if (!files) {
        logger.warning("Cannot read the YARA rules folder: " + files.error().describe());
        return QObject::tr("The YARA rules folder %1 cannot be read: %2")
            .arg(folder, toQString(files.error().describe()));
    }
    if (files.value().empty()) {
        return QObject::tr("The YARA rules folder %1 has no .yar or .yara files.").arg(folder);
    }
    const Result<YaraCompilation> compiled = compileYaraRuleFiles(files.value());
    if (!compiled) {
        logger.warning("Cannot load YARA rules: " + compiled.error().describe());
        return QObject::tr("The YARA rules could not be loaded: %1")
            .arg(toQString(compiled.error().describe()));
    }
    const YaraCompilation& compilation = compiled.value();
    if (!compilation.rules) {
        QStringList errors;
        for (const YaraDiagnostic& diagnostic : compilation.diagnostics) {
            if (!diagnostic.warning) {
                errors.append(QStringLiteral("%1:%2: %3")
                                  .arg(toQString(diagnostic.source))
                                  .arg(diagnostic.line)
                                  .arg(toQString(diagnostic.message)));
            }
        }
        const QString joined = errors.join(QStringLiteral("; "));
        logger.warning("YARA rules did not compile: " + joined.toStdString());
        return QObject::tr("The YARA rules did not compile, so YARA scanning is off: %1")
            .arg(joined);
    }
    enrichments.push_back(std::make_shared<const YaraEnrichment>(compilation.rules));
    logger.info(std::format("Loaded {} YARA rules", compilation.rules->ruleCount()));
    return QObject::tr("%1 YARA rules from %2 files in %3.")
        .arg(compilation.rules->ruleCount())
        .arg(files.value().size())
        .arg(folder);
}
#endif

} // namespace

Application::Application(int& argc, char** argv)
    : logger_(LogLevel::Info, &std::clog)
    , qtApp_(argc, argv) {
    QApplication::setApplicationName(QStringLiteral("Sectoryn"));
    QApplication::setOrganizationName(QStringLiteral("Sectoryn"));
    QApplication::setApplicationVersion(QStringLiteral(SECTORYN_VERSION));
}

Application::~Application() = default;

int Application::run() {
    QCommandLineParser parser;
    parser.setApplicationDescription(
        QStringLiteral("Static PE analysis and malware triage workbench"));
    parser.addHelpOption();
    parser.addVersionOption();
    const QCommandLineOption exitAfterStartup(
        QStringLiteral("exit-after-startup"),
        QStringLiteral("Show the main window, then exit once the event loop starts."));
    parser.addOption(exitAfterStartup);
    parser.addPositionalArgument(QStringLiteral("file"),
                                 QStringLiteral("Optional file to analyze at startup."));
    parser.process(qtApp_);

    config_ = loadUserConfig(logger_);
    logger_.setLevel(config_.logLevel);
    openLogFile();
    logger_.info(std::format("Sectoryn {} starting", SECTORYN_VERSION));
    openHistory();

    Result<AnalysisEngine> engine = createEngine(config_);
    if (!engine) {
        logger_.error("Cannot create the analysis engine: " + engine.error().describe());
        QMessageBox::critical(nullptr, QStringLiteral("Sectoryn"),
                              QStringLiteral("The analysis engine could not be created:\n%1")
                                  .arg(QString::fromStdString(engine.error().describe())));
        return 1;
    }

    auto shared = std::make_shared<const AnalysisEngine>(std::move(engine).value());
    controller_ = std::make_unique<ui::AnalysisController>(shared);
    window_ = std::make_unique<ui::MainWindow>(*controller_);
    window_->addPanel(new ui::OverviewPanel);
    window_->addPanel(new ui::FindingsPanel);
    window_->addPanel(new ui::HeadersView);
    window_->addPanel(new ui::SectionsView);
    window_->addPanel(new ui::ImportsView);
    window_->addPanel(new ui::ExportsView);
    window_->addPanel(new ui::ResourcesView);
    window_->addPanel(new ui::StringsView);
    window_->addPanel(new ui::EntropyPanel);
    window_->addPanel(new ui::SignatureView);
    yaraView_ = new ui::YaraView;
    yaraView_->setRuleStatus(yaraStatus_);
    window_->addPanel(yaraView_);
    window_->addPanel(new ui::ReputationView);
    window_->addPanel(new ui::ReportView);

    jobs_ = std::make_unique<ui::JobManagerView>(shared, batchOptions(config_));
    jobs_->setWindowFlag(Qt::Window);
    QObject::connect(jobs_.get(), &ui::JobManagerView::resultActivated, window_.get(),
                     [this](const ui::SharedResult& result) {
                         window_->showResult(result);
                         window_->activateWindow();
                     });
    QObject::connect(jobs_.get(), &ui::JobManagerView::reanalysisRequested, window_.get(),
                     &ui::MainWindow::analyzeFile);
    QObject::connect(jobs_.get(), &ui::JobManagerView::jobCompleted, window_.get(),
                     [this](const ui::SharedResult& result) { recordHistory(*result); });
    QObject::connect(window_.get(), &ui::MainWindow::resultShown, window_.get(),
                     [this](const ui::SharedResult& result) { showHistoryFor(*result); });
    QAction* batch = window_->toolsMenu()->addAction(QObject::tr("&Batch Analysis..."));
    batch->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_B));
    QObject::connect(batch, &QAction::triggered, jobs_.get(), [this] {
        jobs_->show();
        jobs_->raise();
        jobs_->activateWindow();
    });
    window_->toolsMenu()->addSeparator();
    QAction* clearHistory =
        window_->toolsMenu()->addAction(QObject::tr("Clear Analysis &History"));
    clearHistory->setEnabled(history_.has_value());
    QObject::connect(clearHistory, &QAction::triggered, window_.get(), [this] {
        if (const Status cleared = history_->clear(); !cleared) {
            logger_.warning("Cannot clear the analysis history: " + cleared.error().describe());
        }
        window_->statusBar()->showMessage(QObject::tr("Analysis history cleared"), 4000);
    });
    QAction* settings = window_->toolsMenu()->addAction(QObject::tr("&Settings..."));
    settings->setShortcut(QKeySequence::Preferences);
    QObject::connect(settings, &QAction::triggered, window_.get(), [this] { editSettings(); });

    applyStyleSheet(qtApp_);
    window_->show();

    if (const QStringList files = parser.positionalArguments(); !files.isEmpty()) {
        window_->analyzeFile(files.front());
    }
    if (parser.isSet(exitAfterStartup)) {
        QTimer::singleShot(0, &qtApp_, &QCoreApplication::quit);
    }

    const int status = QApplication::exec();
    jobs_.reset();
    window_.reset();
    controller_.reset();
    logger_.info(std::format("Sectoryn exited with status {}", status));
    return status;
}

Result<AnalysisEngine> Application::createEngine(const Config& config) {
    std::vector<std::shared_ptr<const IEnrichment>> enrichments;
    // Without platform support every file would report verification as unavailable, which
    // only adds noise, so the module is left out.
    std::shared_ptr<const ISignatureVerifier> verifier = createPlatformSignatureVerifier();
    if (verifier->supported()) {
        enrichments.push_back(std::make_shared<const SignatureEnrichment>(std::move(verifier)));
    }
#ifdef SECTORYN_HAVE_YARA
    yaraStatus_ = addYara(config, enrichments, logger_);
#else
    yaraStatus_ = QObject::tr("This build of Sectoryn has no YARA support.");
#endif
    return AnalysisEngine::createDefault({config.limits, {}}, std::move(enrichments));
}

void Application::openHistory() {
    const QString dataDir = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (dataDir.isEmpty()) {
        logger_.warning("No writable application data location; analysis history disabled");
        return;
    }
    const std::filesystem::path file =
        toPath(QDir(dataDir).filePath(QStringLiteral("history.json")));
    Result<HistoryStore> loaded = HistoryStore::load(file);
    if (loaded) {
        history_.emplace(std::move(loaded).value());
        return;
    }
    logger_.warning("Starting a new analysis history; the old one could not be read: " +
                    loaded.error().describe());
    history_.emplace(file);
}

void Application::recordHistory(const AnalysisResult& result) {
    if (!history_ || result.sha256.empty()) {
        return;
    }
    if (const Status saved = history_->record(historyEntryFor(result)); !saved) {
        logger_.warning("Cannot save the analysis history: " + saved.error().describe());
    }
}

void Application::showHistoryFor(const AnalysisResult& result) {
    if (!history_) {
        return;
    }
    const HistoryEntry* previous = history_->find(result.sha256);
    if (previous != nullptr && previous->analyzedAt < result.run.finished) {
        const std::string_view outcome = toString(previous->outcome);
        const auto when = QDateTime::fromMSecsSinceEpoch(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                previous->analyzedAt.time_since_epoch())
                .count());
        window_->statusBar()->showMessage(
            QObject::tr("Analyzed before on %1 as %2: %3")
                .arg(QLocale::system().toString(when, QLocale::ShortFormat),
                     QString::fromStdString(previous->fileName),
                     QString::fromUtf8(outcome.data(), static_cast<qsizetype>(outcome.size()))),
            10000);
    }
    recordHistory(result);
}

void Application::editSettings() {
    ui::SettingsDialog dialog(config_, window_.get());
    if (dialog.exec() != QDialog::Accepted || dialog.config() == config_) {
        return;
    }
    const Config& edited = dialog.config();
    Result<AnalysisEngine> engine = createEngine(edited);
    yaraView_->setRuleStatus(yaraStatus_);
    if (!engine) {
        QMessageBox::warning(window_.get(), QObject::tr("Settings not applied"),
                             QString::fromStdString(engine.error().describe()));
        return;
    }
    if (const Status saved = saveUserConfig(edited); !saved) {
        logger_.warning("Cannot save settings: " + saved.error().describe());
        QMessageBox::warning(window_.get(), QObject::tr("Settings not saved"),
                             QObject::tr("The settings apply until Sectoryn is closed, but "
                                         "they could not be saved:\n%1")
                                 .arg(QString::fromStdString(saved.error().describe())));
    }
    config_ = edited;
    logger_.setLevel(config_.logLevel);
    auto shared = std::make_shared<const AnalysisEngine>(std::move(engine).value());
    controller_->setEngine(shared);
    jobs_->configure(shared, batchOptions(config_));
    logger_.info("Settings changed");
}

void Application::openLogFile() {
    const QString dataDir = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (dataDir.isEmpty()) {
        logger_.warning("No writable application data location; file logging disabled");
        return;
    }
    const std::filesystem::path logPath =
        toPath(QDir(dataDir).filePath(QStringLiteral("logs"))) / "sectoryn.log";
    if (const Status opened = logger_.openFile(logPath, kMaxLogFileBytes); !opened) {
        logger_.warning("File logging disabled: " + opened.error().describe());
    }
}

} // namespace sectoryn
