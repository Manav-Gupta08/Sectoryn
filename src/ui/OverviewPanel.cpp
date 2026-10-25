#include "ui/OverviewPanel.hpp"

#include "parsers/PeConstants.hpp"
#include "ui/Formatting.hpp"

#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLocale>
#include <QPlainTextEdit>
#include <QScrollArea>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <numeric>

namespace sectoryn::ui {

namespace {

// No outcome is shown in green: "no significant indicators" is not the same as "safe".
QColor outcomeColor(TriageOutcome outcome) {
    switch (outcome) {
    case TriageOutcome::HighPriority:
        return severityColor(Severity::High);
    case TriageOutcome::SuspiciousIndicators:
        return severityColor(Severity::Medium);
    case TriageOutcome::AnalysisIncomplete:
        return QColor(0xb0, 0x8d, 0x57);
    case TriageOutcome::NoSignificantIndicators:
    case TriageOutcome::UnsupportedOrInvalid:
        return severityColor(Severity::Informational);
    }
    return severityColor(Severity::Informational);
}

QString duration(const RunInfo& run) {
    const auto ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(run.finished - run.started).count();
    return QObject::tr("%1 ms").arg(QLocale::system().toString(static_cast<qlonglong>(ms)));
}

QString findingSummary(const std::vector<Finding>& findings) {
    if (findings.empty()) {
        return QObject::tr("none");
    }
    std::array<int, 5> counts{};
    for (const Finding& finding : findings) {
        ++counts[static_cast<std::size_t>(finding.severity)];
    }
    QStringList parts;
    for (int severity = static_cast<int>(Severity::Critical); severity >= 0; --severity) {
        if (const int count = counts[static_cast<std::size_t>(severity)]; count > 0) {
            parts.append(QStringLiteral("%1 %2").arg(count).arg(
                severityText(static_cast<Severity>(severity)).toLower()));
        }
    }
    return parts.join(QStringLiteral(", "));
}

QString importSummary(const ImportTable& imports) {
    if (!imports.status.hasData() && !imports.delayStatus.hasData()) {
        return fieldStatusText(imports.status);
    }
    const auto functions = std::accumulate(
        imports.modules.begin(), imports.modules.end(), std::size_t{0},
        [](std::size_t sum, const ImportedModule& m) { return sum + m.functions.size(); });
    return QObject::tr("%1 functions from %2 modules").arg(functions).arg(imports.modules.size());
}

} // namespace

OverviewPanel::OverviewPanel(QWidget* parent)
    : AnalysisPanel(parent)
    , outcome_(new QLabel(this))
    , score_(new QLabel(this))
    , facts_(new QFormLayout)
    , explanation_(new QPlainTextEdit(this)) {
    auto* content = new QWidget(this);
    auto* layout = new QVBoxLayout(content);
    layout->setContentsMargins(16, 16, 16, 16);

    outcome_->setObjectName(QStringLiteral("outcomeBadge"));
    outcome_->setTextFormat(Qt::PlainText);
    score_->setTextFormat(Qt::PlainText);
    auto* header = new QHBoxLayout;
    header->addWidget(outcome_);
    header->addWidget(score_);
    header->addStretch();

    facts_->setLabelAlignment(Qt::AlignRight);
    facts_->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);

    explanation_->setReadOnly(true);
    explanation_->setMinimumHeight(120);
    explanation_->setAccessibleName(tr("Assessment details"));

    layout->addLayout(header);
    layout->addSpacing(8);
    layout->addLayout(facts_);
    layout->addSpacing(8);
    layout->addWidget(explanation_, 1);

    auto* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setWidget(content);
    setContent(scroll);
    clear();
}

void OverviewPanel::clear() {
    showMessage(tr("Open a file to see its analysis."));
}

void OverviewPanel::addRow(const QString& label, const QString& value) {
    auto* field = new QLabel(value);
    field->setTextFormat(Qt::PlainText);
    field->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    field->setWordWrap(true);
    facts_->addRow(label, field);
}

void OverviewPanel::showResult(const SharedResult& result) {
    while (facts_->rowCount() > 0) {
        facts_->removeRow(0);
    }
    const AnalysisResult& r = *result;
    const RiskAssessment& risk = r.risk;

    outcome_->setText(toQString(toString(risk.outcome)));
    outcome_->setStyleSheet(QStringLiteral("background-color: %1; color: #101214;")
                                .arg(outcomeColor(risk.outcome).name()));
    score_->setText(risk.outcome == TriageOutcome::UnsupportedOrInvalid
                        ? QString()
                        : tr("Score %1 / %2").arg(risk.score, 0, 'f', 1).arg(
                              RiskAssessment::kMaxScore, 0, 'f', 0));

    const QString path = QString::fromStdU16String(r.file.path.u16string());
    addRow(tr("File"), QFileInfo(path).fileName());
    addRow(tr("Location"), QFileInfo(path).absolutePath());
    addRow(tr("Size"), byteSize(r.file.sizeBytes));
    addRow(tr("SHA-256"), toQString(r.sha256));
    addRow(tr("Format"), r.identification.kind == FileKind::Pe && r.pe
                             ? (r.pe->format == PeFormat::Pe32Plus ? tr("PE32+ (64-bit)")
                                                                   : tr("PE32 (32-bit)"))
                             : toQString(r.identification.detail));

    if (r.pe) {
        const PeImage& pe = *r.pe;
        const bool dll = (pe.coff.characteristics & pe::kFileDll) != 0;
        addRow(tr("Kind"), dll ? tr("Dynamic-link library") : tr("Executable"));
        addRow(tr("Architecture"), QStringLiteral("%1 (%2)").arg(
                                       toQString(pe::machineName(pe.coff.machine)),
                                       hex(pe.coff.machine, 4)));
        addRow(tr("Subsystem"), toQString(pe::subsystemName(pe.optional.subsystem)));
        addRow(tr("Link timestamp"),
               coffTimestamp(pe.coff.timeDateStamp) + tr(" - set by the linker; can be forged"));
        addRow(tr("Entry point"), tr("RVA %1").arg(hex(pe.optional.addressOfEntryPoint, 8)));
        addRow(tr("Image base"), hex(pe.optional.imageBase));
        addRow(tr("Sections"), QString::number(pe.sections.size()));
        addRow(tr("Imports"), importSummary(pe.imports));
        addRow(tr("Exports"), pe.exports.status.hasData()
                                  ? tr("%1 functions").arg(pe.exports.functions.size())
                                  : fieldStatusText(pe.exports.status));
        addRow(tr("Overlay"), pe.overlay.status.state == FieldState::Present
                                  ? tr("%1 at %2").arg(byteSize(pe.overlay.size),
                                                       hex(pe.overlay.fileOffset))
                                  : fieldStatusText(pe.overlay.status));
    }
    addRow(tr("Findings"), findingSummary(r.findings));
    addRow(tr("Engine"), tr("Sectoryn %1, %2 %3")
                             .arg(toQString(r.engine.version), toQString(r.engine.parserName),
                                  toQString(r.engine.parserVersion)));
    addRow(tr("Analysis time"), duration(r.run));

    QStringList details{toQString(risk.explanation)};
    if (!risk.coverageGaps.empty()) {
        details.append(QString());
        details.append(tr("Not fully analyzed:"));
        for (const std::string& gap : risk.coverageGaps) {
            details.append(QStringLiteral("  - %1").arg(toQString(gap)));
        }
    }
    explanation_->setPlainText(details.join(QLatin1Char('\n')));
    showContent();
}

} // namespace sectoryn::ui
