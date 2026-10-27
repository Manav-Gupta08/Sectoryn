#include "engine/AnalysisEngine.hpp"
#include "reports/HtmlReport.hpp"
#include "support/PeBuilder.hpp"
#include "support/TempDir.hpp"
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
#include "ui/models/ExportTableModel.hpp"
#include "ui/models/FindingTableModel.hpp"
#include "ui/models/ImportTableModel.hpp"
#include "ui/models/JobTableModel.hpp"
#include "ui/models/ResourceTableModel.hpp"
#include "ui/models/SectionTableModel.hpp"
#include "ui/models/StringTableModel.hpp"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QTabWidget>
#include <QTextBrowser>
#include <QTimer>
#include <QTreeWidget>

#include <gtest/gtest.h>

#include <algorithm>
#include <memory>

namespace sectoryn::ui {
namespace {

using namespace std::string_literals;
using test::bytesOf;
using test::PeBuilder;

QApplication& application() {
    if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM")) {
        qputenv("QT_QPA_PLATFORM", "offscreen");
    }
    static int argc = 1;
    static char name[] = "sectoryn_ui_tests";
    static char* argv[] = {name, nullptr};
    static QApplication app(argc, argv);
    return app;
}

std::shared_ptr<const AnalysisEngine> engine() {
    static const std::shared_ptr<const AnalysisEngine> instance = [] {
        Result<AnalysisEngine> created = AnalysisEngine::createDefault();
        EXPECT_TRUE(created.hasValue());
        return std::make_shared<const AnalysisEngine>(std::move(created).value());
    }();
    return instance;
}

std::vector<std::byte> sampleDll() {
    return PeBuilder(PeFormat::Pe32Plus)
        .characteristics(0x2022)
        .addSection(".text", PeBuilder::kCode, bytesOf(std::string(0x400, '\xCC')))
        .addSection(".rwx", 0xE0000020, bytesOf("<b>not markup</b>\0http://c2.example.org/x\0"s))
        .addImport("KERNEL32.dll",
                   {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"})
        .addImport("WS2_32.dll", {"#23"})
        .exports("sample.dll", {"Start", "Stop"})
        .build();
}

class UiTest : public ::testing::Test {
protected:
    void SetUp() override {
        application();
        const auto path = dir_.write("sample.dll", sampleDll());
        Result<AnalysisResult> analyzed = engine()->analyze(path);
        ASSERT_TRUE(analyzed.hasValue()) << analyzed.error().describe();
        result_ = std::make_shared<const AnalysisResult>(std::move(analyzed).value());
    }

    const Finding& finding(std::string_view id) const {
        const auto it = std::ranges::find(result_->findings, id, &Finding::ruleId);
        EXPECT_NE(it, result_->findings.end()) << id;
        return *it;
    }

    test::TempDir dir_;
    SharedResult result_;
};

TEST_F(UiTest, SectionModelExposesSections) {
    SectionTableModel model;
    model.setResult(result_);
    ASSERT_EQ(model.rowCount(), static_cast<int>(result_->pe->sections.size()));
    EXPECT_EQ(model.index(0, SectionTableModel::NameColumn).data().toString(),
              QStringLiteral(".text"));
    EXPECT_EQ(model.index(1, SectionTableModel::PermissionsColumn).data().toString(),
              QStringLiteral("RWX"));
    EXPECT_EQ(model.index(0, SectionTableModel::VirtualAddressColumn)
                  .data(SectionTableModel::SortRole)
                  .toULongLong(),
              0x1000U);
    EXPECT_TRUE(model.index(1, SectionTableModel::PermissionsColumn)
                    .data(Qt::ForegroundRole)
                    .isValid());

    model.setResult(nullptr);
    EXPECT_EQ(model.rowCount(), 0);
}

TEST_F(UiTest, ImportAndExportModels) {
    ImportTableModel imports;
    imports.setResult(result_);
    EXPECT_EQ(imports.rowCount(), 5);
    EXPECT_GE(imports.findRow(u"KERNEL32.dll", u"WriteProcessMemory"), 0);
    EXPECT_EQ(imports.findRow(u"KERNEL32.dll", u"Missing"), -1);
    const int ordinalRow = imports.findRow(u"WS2_32.dll", u"");
    ASSERT_GE(ordinalRow, 0);
    EXPECT_EQ(imports.index(ordinalRow, ImportTableModel::OrdinalColumn).data().toInt(), 23);

    ExportTableModel exports;
    exports.setResult(result_);
    ASSERT_EQ(exports.rowCount(), 2);
    EXPECT_EQ(exports.index(0, ExportTableModel::NameColumn).data().toString(),
              QStringLiteral("Start"));
}

TEST_F(UiTest, StringModelLinksIndicators) {
    StringTableModel model;
    model.setResult(result_);
    ASSERT_EQ(model.rowCount(), static_cast<int>(result_->strings->strings.size()));

    const auto url = std::ranges::find(result_->indicators, IndicatorKind::Url, &Indicator::kind);
    ASSERT_NE(url, result_->indicators.end());
    const int row = model.rowContaining(url->offset);
    ASSERT_GE(row, 0);
    EXPECT_TRUE(model.index(row, 0).data(StringTableModel::HasIndicatorRole).toBool());
    EXPECT_TRUE(model.index(row, StringTableModel::TextColumn)
                    .data()
                    .toString()
                    .contains(QStringLiteral("http://c2.example.org/x")));
}

TEST_F(UiTest, FindingModelShowsSeverityAndScore) {
    FindingTableModel model;
    model.setResult(result_);
    ASSERT_EQ(model.rowCount(), static_cast<int>(result_->findings.size()));
    for (int row = 0; row < model.rowCount(); ++row) {
        EXPECT_FALSE(model.index(row, FindingTableModel::TitleColumn).data().toString().isEmpty());
        EXPECT_FALSE(model.index(row, FindingTableModel::ScoreColumn).data().toString().isEmpty());
    }
}

TEST_F(UiTest, PanelsRevealTheirEvidence) {
    SectionsView sections;
    sections.showResult(result_);
    EXPECT_TRUE(sections.reveal(finding("section.writable_executable").evidence.front()));

    ImportsView imports;
    imports.showResult(result_);
    EXPECT_TRUE(imports.reveal(finding("api.process_injection").evidence.front()));

    StringsView strings;
    strings.showResult(result_);
    EXPECT_TRUE(strings.reveal(finding("strings.network").evidence.front()));

    EXPECT_FALSE(sections.reveal(finding("strings.network").evidence.front()));
}

TEST_F(UiTest, MainWindowShowsResultsInEveryPanel) {
    AnalysisController controller(engine());
    MainWindow window(controller);
    for (AnalysisPanel* panel : std::initializer_list<AnalysisPanel*>{
             new OverviewPanel, new FindingsPanel, new HeadersView, new SectionsView,
             new ImportsView, new ExportsView, new ResourcesView, new StringsView,
             new EntropyPanel, new SignatureView, new YaraView, new ReputationView,
             new ReportView}) {
        window.addPanel(panel);
    }
    window.resize(1280, 800);
    window.show();
    window.showResult(result_);
    EXPECT_EQ(window.currentResult(), result_);

    // Snapshots for documentation and visual review, written only when requested.
    const QString snapshots = qEnvironmentVariable("SECTORYN_UI_SNAPSHOT_DIR");
    if (QFile style(QStringLiteral(":/styles/dark.qss"));
        !snapshots.isEmpty() && style.open(QIODevice::ReadOnly)) {
        application().setStyleSheet(QString::fromUtf8(style.readAll()));
    }
    auto* tabs = window.findChild<QTabWidget*>();
    ASSERT_NE(tabs, nullptr);
    for (int i = 0; i < tabs->count(); ++i) {
        tabs->setCurrentIndex(i);
        const QPixmap image = window.grab();
        EXPECT_FALSE(image.isNull());
        if (!snapshots.isEmpty()) {
            image.save(QDir(snapshots).filePath(QStringLiteral("tab%1.png").arg(i)));
        }
    }
}

TEST_F(UiTest, ReportViewRendersWhenShown) {
    ReportView view;
    view.resize(900, 600);
    view.showResult(result_);
    auto* html = view.findChild<QTextBrowser*>();
    auto* json = view.findChild<QPlainTextEdit*>();
    auto* format = view.findChild<QComboBox*>();
    ASSERT_NE(html, nullptr);
    ASSERT_NE(json, nullptr);
    ASSERT_NE(format, nullptr);
    EXPECT_TRUE(html->toPlainText().isEmpty()) << "hidden views should not render";

    view.show();
    EXPECT_TRUE(html->toPlainText().contains(QStringLiteral("Findings")));
    EXPECT_TRUE(html->toPlainText().contains(QStringLiteral("http://c2.example.org/x")));
    EXPECT_FALSE(html->toPlainText().contains(QStringLiteral("not markup")));

    // Markup in a string must come through as text, not be interpreted.
    const auto boxes = view.findChildren<QCheckBox*>();
    const auto strings = std::ranges::find_if(boxes, [](const QCheckBox* box) {
        return box->text().contains(QStringLiteral("strings"));
    });
    ASSERT_NE(strings, boxes.end());
    (*strings)->setChecked(true);
    EXPECT_TRUE(html->toPlainText().contains(QStringLiteral("<b>not markup</b>")));

    format->setCurrentIndex(1);
    EXPECT_TRUE(json->toPlainText().startsWith(QLatin1Char('{')));
    EXPECT_TRUE(json->toPlainText().contains(QStringLiteral("\"schema\": \"sectoryn-report\"")));

    if (const QString snapshots = qEnvironmentVariable("SECTORYN_UI_SNAPSHOT_DIR");
        !snapshots.isEmpty()) {
        QFile file(QDir(snapshots).filePath(QStringLiteral("report.html")));
        ASSERT_TRUE(file.open(QIODevice::WriteOnly));
        const std::string report = renderHtmlReport(*result_);
        file.write(report.data(), static_cast<qint64>(report.size()));
    }
}

// Finds a form field by the text of its label, the way a user would.
QSpinBox* spinFor(const QWidget& parent, const QString& label) {
    for (const QLabel* candidate : parent.findChildren<QLabel*>()) {
        if (candidate->text() == label) {
            return qobject_cast<QSpinBox*>(candidate->buddy());
        }
    }
    return nullptr;
}

TEST_F(UiTest, SettingsDialogReturnsEditedCopy) {
    Config original;
    original.limits.maxFileBytes = 3 * kMiB / 2;
    SettingsDialog dialog(original);
    QSpinBox* workers = spinFor(dialog, QStringLiteral("Batch &worker threads:"));
    ASSERT_NE(workers, nullptr);
    EXPECT_EQ(workers->value(), 2);

    workers->setValue(5);
    dialog.accept();
    EXPECT_EQ(dialog.result(), QDialog::Accepted);
    EXPECT_EQ(dialog.config().workerCount, 5U);
    // Shown as 2 MiB, but kept exact because the user did not change it.
    EXPECT_EQ(dialog.config().limits.maxFileBytes, 3 * kMiB / 2);
}

TEST_F(UiTest, SettingsDialogRefusesInvalidValues) {
    const Config original;
    SettingsDialog dialog(original);
    QSpinBox* minLength = spinFor(dialog, QStringLiteral("M&inimum length:"));
    QSpinBox* maxLength = spinFor(dialog, QStringLiteral("Maximum len&gth:"));
    ASSERT_NE(minLength, nullptr);
    ASSERT_NE(maxLength, nullptr);

    minLength->setValue(100);
    maxLength->setValue(50);
    dialog.accept();
    EXPECT_NE(dialog.result(), QDialog::Accepted);
    EXPECT_EQ(dialog.config(), original);
    auto* error = dialog.findChild<QLabel*>(QStringLiteral("errorText"));
    ASSERT_NE(error, nullptr);
    EXPECT_FALSE(error->isHidden());
    EXPECT_TRUE(error->text().contains(QStringLiteral("min_string_length")));
}

TEST_F(UiTest, SettingsDialogEditsYaraFolder) {
    const Config original;
    SettingsDialog dialog(original);
    const auto edits = dialog.findChildren<QLineEdit*>();
    const auto folder = std::ranges::find_if(edits, [](const QLineEdit* edit) {
        return edit->placeholderText().contains(QStringLiteral("YARA"));
    });
    ASSERT_NE(folder, edits.end());
    EXPECT_TRUE((*folder)->text().isEmpty());

    (*folder)->setText(QStringLiteral("rules/yara"));
    dialog.accept();
    EXPECT_EQ(dialog.result(), QDialog::Accepted);
    EXPECT_EQ(dialog.config().yaraRulesDirectory, std::filesystem::path("rules/yara"));
}

// Lists the text of every item in a tree, depth first.
QStringList treeText(const QTreeWidget& tree) {
    QStringList text;
    std::vector<QTreeWidgetItem*> pending;
    for (int i = tree.topLevelItemCount() - 1; i >= 0; --i) {
        pending.push_back(tree.topLevelItem(i));
    }
    while (!pending.empty()) {
        QTreeWidgetItem* item = pending.back();
        pending.pop_back();
        for (int column = 0; column < item->columnCount(); ++column) {
            text.append(item->text(column));
        }
        for (int i = item->childCount() - 1; i >= 0; --i) {
            pending.push_back(item->child(i));
        }
    }
    return text;
}

TEST_F(UiTest, ResourceModelNamesPredefinedTypes) {
    AnalysisResult copy = *result_;
    copy.pe->resources.status = FieldStatus::present();
    copy.pe->resources.directoryCount = 3;
    copy.pe->resources.entries = {
        {.type = {3, {}}, .name = {1, {}}, .language = {0x409, {}}, .fileOffset = 0x2000,
         .size = 0x128, .codePage = 0},
        {.type = {std::nullopt, "CUSTOM"}, .name = {std::nullopt, "<b>DATA</b>"},
         .language = {0, {}}, .fileOffset = 0x2200, .size = 16, .codePage = 1252},
    };
    const auto shared = std::make_shared<const AnalysisResult>(std::move(copy));

    ResourceTableModel model;
    model.setResult(shared);
    ASSERT_EQ(model.rowCount(), 2);
    EXPECT_EQ(model.index(0, ResourceTableModel::TypeColumn).data().toString(),
              QStringLiteral("RT_ICON (3)"));
    EXPECT_EQ(model.index(1, ResourceTableModel::TypeColumn).data().toString(),
              QStringLiteral("CUSTOM"));
    EXPECT_EQ(model.index(1, ResourceTableModel::NameColumn).data().toString(),
              QStringLiteral("<b>DATA</b>"));
    EXPECT_EQ(model.index(0, ResourceTableModel::LanguageColumn).data().toString(),
              QStringLiteral("0x0409"));

    ResourcesView view;
    view.showResult(shared);
    const auto labels = view.findChildren<QLabel*>();
    EXPECT_TRUE(std::ranges::any_of(labels, [](const QLabel* label) {
        return label->text().contains(QStringLiteral("2 entries in 3 directories"));
    }));
}

TEST_F(UiTest, SignatureViewSaysWhenVerificationDidNotRun) {
    SignatureView view;
    view.showResult(result_);
    auto* tree = view.findChild<QTreeWidget*>();
    ASSERT_NE(tree, nullptr);
    const QString text = treeText(*tree).join(QLatin1Char('\n'));
    EXPECT_TRUE(text.contains(QStringLiteral("Certificate table")));
    EXPECT_TRUE(text.contains(QStringLiteral("Not performed")));
}

TEST_F(UiTest, YaraViewListsMatchesWithOffsets) {
    YaraView empty;
    empty.setRuleStatus(QStringLiteral("No rules configured for this test."));
    empty.showResult(result_);
    auto* message = empty.findChild<QLabel*>(QStringLiteral("panelMessage"));
    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->text().contains(QStringLiteral("No rules configured")));

    AnalysisResult copy = *result_;
    EnrichmentResult yara;
    yara.id = "yara";
    yara.displayName = "YARA rules";
    yara.status = FieldStatus::present();
    copy.enrichments.push_back(yara);
    Finding match;
    match.ruleId = "yara.Example_Rule";
    match.description = "test rule";
    match.severity = Severity::High;
    match.evidence.push_back({.description = "$a matched 4 bytes",
                              .fileOffset = 0x420,
                              .location = "YARA rules 'test'"});
    copy.findings.push_back(match);

    YaraView view;
    view.showResult(std::make_shared<const AnalysisResult>(std::move(copy)));
    auto* tree = view.findChild<QTreeWidget*>();
    ASSERT_NE(tree, nullptr);
    const QStringList text = treeText(*tree);
    EXPECT_TRUE(text.contains(QStringLiteral("Example_Rule")));
    EXPECT_TRUE(text.contains(QStringLiteral("0x00000420")));
}

TEST_F(UiTest, ReputationLookupNeedsConsentAndKey) {
    ReputationView view;
    view.showResult(result_);
    auto* consent = view.findChild<QCheckBox*>();
    auto* key = view.findChild<QLineEdit*>();
    auto* button = view.findChild<QPushButton*>();
    ASSERT_NE(consent, nullptr);
    ASSERT_NE(key, nullptr);
    ASSERT_NE(button, nullptr);

    EXPECT_FALSE(consent->isChecked()) << "lookups are off by default";
    EXPECT_FALSE(button->isEnabled());
    key->setText(QStringLiteral("abc123"));
    EXPECT_FALSE(button->isEnabled());
    consent->setChecked(true);
    EXPECT_TRUE(button->isEnabled());
    consent->setChecked(false);
    EXPECT_FALSE(button->isEnabled());
    EXPECT_EQ(key->echoMode(), QLineEdit::Password);

    view.clear();
    EXPECT_FALSE(button->isEnabled());
}

TEST_F(UiTest, NonPeResultIsExplainedNotHidden) {
    const auto path = dir_.write("notes.txt", bytesOf("plain text"));
    Result<AnalysisResult> analyzed = engine()->analyze(path);
    ASSERT_TRUE(analyzed.hasValue());
    const SharedResult text = std::make_shared<const AnalysisResult>(std::move(analyzed).value());

    SectionsView sections;
    sections.showResult(text);
    FindingsPanel findings;
    findings.showResult(text);
    SectionTableModel model;
    model.setResult(text);
    EXPECT_EQ(model.rowCount(), 0);
}

TEST_F(UiTest, JobModelTracksStatesAndBoundsRetainedResults) {
    JobTableModel model;
    const auto count = static_cast<JobId>(JobTableModel::kMaxRetainedResults + 2);
    const std::filesystem::path path("job.exe");
    for (JobId id = 1; id <= count; ++id) {
        model.apply({.id = id, .path = path, .state = JobState::Queued});
        model.apply({.id = id, .path = path, .state = JobState::Completed, .result = result_});
    }
    model.apply({.id = 100, .path = path, .state = JobState::Duplicate, .duplicateOf = 1});

    EXPECT_EQ(model.rowCount(), static_cast<int>(count) + 1);
    EXPECT_EQ(model.count(JobState::Completed), count);
    EXPECT_EQ(model.jobAt(0)->result, nullptr) << "the oldest results are released";
    EXPECT_NE(model.jobAt(static_cast<int>(count) - 1)->result, nullptr);
    EXPECT_EQ(model.jobAt(0)->outcome, result_->risk.outcome) << "the summary is kept";
    const QModelIndex detail = model.index(static_cast<int>(count), JobTableModel::DetailColumn);
    EXPECT_TRUE(model.data(detail, Qt::DisplayRole).toString().contains(QStringLiteral("job 1")));

    model.apply({.id = 200, .path = path, .state = JobState::Running});
    model.removeFinished();
    ASSERT_EQ(model.rowCount(), 1);
    EXPECT_EQ(model.jobAt(0)->id, 200U);
}

TEST_F(UiTest, JobManagerRunsBatchesAndRecognizesDuplicates) {
    JobManagerView view(engine(), {.workerCount = 2, .maxQueuedJobs = 8});
    const std::vector<std::byte> copy = sampleDll();
    const QStringList files = {
        QString::fromStdU16String(dir_.write("one.dll", copy).u16string()),
        QString::fromStdU16String(dir_.write("two.dll", copy).u16string()),
        QString::fromStdU16String(dir_.write("text.txt", bytesOf("plain text")).u16string())};
    EXPECT_EQ(view.addFiles(files), 3);

    const JobTableModel& model = view.model();
    const auto finished = [&model] {
        return model.count(JobState::Completed) + model.count(JobState::Duplicate) +
               model.count(JobState::Failed) + model.count(JobState::Cancelled);
    };
    QElapsedTimer timer;
    timer.start();
    while (finished() < 3 && timer.elapsed() < 30000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    }
    EXPECT_EQ(model.count(JobState::Completed), 2U);
    EXPECT_EQ(model.count(JobState::Duplicate), 1U);
}

TEST_F(UiTest, JobManagerQueuesFolderContents) {
    const test::TempDir folder;
    for (const char* name : {"a.bin", "b.bin", "c.bin"}) {
        static_cast<void>(folder.write(name, std::string_view(name)));
    }
    JobManagerView view(engine(), {.workerCount = 1, .maxQueuedJobs = 8});
    EXPECT_EQ(view.addFolder(QString::fromStdU16String(folder.path().u16string())), 3);
    EXPECT_EQ(view.model().rowCount(), 0) << "rows appear once the queued updates arrive";
    QCoreApplication::processEvents();
    EXPECT_EQ(view.model().rowCount(), 3);
    view.cancelAll();
}

// Waits for `controller` to report an outcome, failing after a generous timeout.
template <typename Signal>
bool waitFor(AnalysisController& controller, Signal signal) {
    QEventLoop loop;
    bool fired = false;
    QObject::connect(&controller, signal, &loop, [&] {
        fired = true;
        loop.quit();
    });
    QTimer::singleShot(30000, &loop, &QEventLoop::quit);
    loop.exec();
    return fired;
}

TEST_F(UiTest, ControllerRunsAnalysisOffTheUiThread) {
    AnalysisController controller(engine());
    SharedResult received;
    std::vector<AnalysisStage> stages;
    QObject::connect(&controller, &AnalysisController::finished,
                     [&](const SharedResult& result) { received = result; });
    QObject::connect(&controller, &AnalysisController::progressed,
                     [&](AnalysisStage stage) { stages.push_back(stage); });

    const auto path = dir_.write("again.dll", sampleDll());
    ASSERT_TRUE(controller.analyze(QString::fromStdU16String(path.u16string())));
    EXPECT_TRUE(controller.isBusy());
    EXPECT_FALSE(controller.analyze(QStringLiteral("second.exe")));
    ASSERT_TRUE(waitFor(controller, &AnalysisController::finished));
    ASSERT_NE(received, nullptr);
    EXPECT_EQ(received->sha256, result_->sha256);
    EXPECT_FALSE(controller.isBusy());
    EXPECT_FALSE(stages.empty());
}

TEST_F(UiTest, ControllerReportsFailures) {
    AnalysisController controller(engine());
    QString message;
    QObject::connect(&controller, &AnalysisController::failed,
                     [&](const QString&, const QString& text) { message = text; });
    ASSERT_TRUE(controller.analyze(QDir(QString::fromStdU16String(dir_.path().u16string()))
                                       .filePath(QStringLiteral("missing.exe"))));
    ASSERT_TRUE(waitFor(controller, &AnalysisController::failed));
    EXPECT_FALSE(message.isEmpty());
}

TEST_F(UiTest, ControllerCanBeDestroyedWhileBusy) {
    const auto path = dir_.write("busy.dll", sampleDll());
    for (int i = 0; i < 5; ++i) {
        AnalysisController controller(engine());
        ASSERT_TRUE(controller.analyze(QString::fromStdU16String(path.u16string())));
        controller.cancel();
    }
    // Pending queued calls for destroyed controllers must be dropped without crashing.
    QCoreApplication::processEvents();
    SUCCEED();
}

} // namespace
} // namespace sectoryn::ui
