#include "ui/FindingsPanel.hpp"

#include "ui/Formatting.hpp"
#include "ui/models/FindingTableModel.hpp"

#include <QComboBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QSortFilterProxyModel>
#include <QSplitter>
#include <QTableView>
#include <QVBoxLayout>

namespace sectoryn::ui {

class FindingFilterModel final : public QSortFilterProxyModel {
public:
    using QSortFilterProxyModel::QSortFilterProxyModel;

    void setMinimumSeverity(int severity) {
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
        beginFilterChange();
        minimum_ = severity;
        endFilterChange(Direction::Rows);
#else
        minimum_ = severity;
        invalidateFilter();
#endif
    }

protected:
    bool filterAcceptsRow(int row, const QModelIndex& parent) const override {
        const QModelIndex index = sourceModel()->index(row, 0, parent);
        if (index.data(FindingTableModel::SeverityRole).toInt() < minimum_) {
            return false;
        }
        return QSortFilterProxyModel::filterAcceptsRow(row, parent);
    }

private:
    int minimum_ = 0;
};

namespace {

QString section(const QString& heading, const QString& body) {
    return body.isEmpty() ? QString() : QStringLiteral("%1\n%2\n\n").arg(heading, body);
}

} // namespace

FindingsPanel::FindingsPanel(QWidget* parent)
    : AnalysisPanel(parent)
    , model_(new FindingTableModel(this))
    , filter_(new FindingFilterModel(this))
    , search_(new QLineEdit(this))
    , minimumSeverity_(new QComboBox(this))
    , table_(new QTableView(this))
    , details_(new QPlainTextEdit(this))
    , evidence_(new QListWidget(this))
    , evidenceHint_(new QLabel(this)) {
    filter_->setSourceModel(model_);
    filter_->setFilterKeyColumn(-1);
    filter_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    filter_->setSortRole(FindingTableModel::SortRole);

    search_->setPlaceholderText(tr("Search findings"));
    search_->setClearButtonEnabled(true);
    connect(search_, &QLineEdit::textChanged, filter_,
            &QSortFilterProxyModel::setFilterFixedString);

    for (int severity = static_cast<int>(Severity::Informational);
         severity <= static_cast<int>(Severity::Critical); ++severity) {
        minimumSeverity_->addItem(
            tr("%1 and above").arg(severityText(static_cast<Severity>(severity))), severity);
    }
    minimumSeverity_->setAccessibleName(tr("Minimum severity"));
    connect(minimumSeverity_, &QComboBox::currentIndexChanged, this, [this](int index) {
        filter_->setMinimumSeverity(minimumSeverity_->itemData(index).toInt());
    });

    table_->setModel(filter_);
    table_->setSortingEnabled(true);
    table_->sortByColumn(FindingTableModel::SeverityColumn, Qt::DescendingOrder);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->hide();
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(FindingTableModel::TitleColumn,
                                                     QHeaderView::Stretch);
    table_->setAccessibleName(tr("Findings"));
    connect(table_->selectionModel(), &QItemSelectionModel::currentRowChanged, this,
            [this](const QModelIndex& current) {
                showFinding(current.isValid() ? filter_->mapToSource(current).row() : -1);
            });

    details_->setReadOnly(true);
    details_->setAccessibleName(tr("Finding details"));
    evidence_->setAccessibleName(tr("Evidence"));
    connect(evidence_, &QListWidget::itemActivated, this, [this](QListWidgetItem* item) {
        if (!result_ || currentFinding_ < 0) {
            return;
        }
        const auto& items = result_->findings[static_cast<std::size_t>(currentFinding_)].evidence;
        const auto row = static_cast<std::size_t>(evidence_->row(item));
        if (row < items.size()) {
            Q_EMIT evidenceActivated(items[row]);
        }
    });
    evidenceHint_->setObjectName(QStringLiteral("mutedText"));
    evidenceHint_->setText(tr("Double-click or press Enter on evidence to see where it is."));

    auto* filters = new QHBoxLayout;
    filters->addWidget(search_, 1);
    filters->addWidget(minimumSeverity_);

    auto* evidencePane = new QWidget(this);
    auto* evidenceLayout = new QVBoxLayout(evidencePane);
    evidenceLayout->setContentsMargins(0, 0, 0, 0);
    evidenceLayout->addWidget(evidence_, 1);
    evidenceLayout->addWidget(evidenceHint_);

    auto* lower = new QSplitter(Qt::Horizontal, this);
    lower->addWidget(details_);
    lower->addWidget(evidencePane);
    lower->setStretchFactor(0, 3);
    lower->setStretchFactor(1, 2);

    auto* splitter = new QSplitter(Qt::Vertical, this);
    splitter->addWidget(table_);
    splitter->addWidget(lower);
    splitter->setStretchFactor(0, 1);
    splitter->setStretchFactor(1, 1);

    auto* content = new QWidget(this);
    auto* layout = new QVBoxLayout(content);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addLayout(filters);
    layout->addWidget(splitter, 1);
    setContent(content);
    clear();
}

void FindingsPanel::clear() {
    result_.reset();
    model_->setResult(nullptr);
    showFinding(-1);
    showMessage(tr("Open a file to see its findings."));
}

void FindingsPanel::showResult(const SharedResult& result) {
    result_ = result;
    model_->setResult(result);
    showFinding(-1);
    if (result->risk.outcome == TriageOutcome::UnsupportedOrInvalid) {
        showMessage(tr("No rules were run.\n\n%1").arg(toQString(result->risk.explanation)));
        return;
    }
    if (result->findings.empty()) {
        showMessage(result->risk.coverageGaps.empty()
                        ? tr("No rule matched. This does not mean the file is safe; static rules "
                             "cannot see everything a program does.")
                        : tr("No rule matched, but parts of the analysis did not complete. See the "
                             "Overview tab for what is missing."));
        return;
    }
    table_->selectRow(0);
    showContent();
}

void FindingsPanel::showFinding(int row) {
    currentFinding_ = row;
    evidence_->clear();
    if (!result_ || row < 0 || static_cast<std::size_t>(row) >= result_->findings.size()) {
        details_->clear();
        return;
    }
    const Finding& finding = result_->findings[static_cast<std::size_t>(row)];

    QStringList attack;
    for (const AttackTechnique& technique : finding.attack) {
        attack.append(
            QStringLiteral("%1 %2").arg(toQString(technique.id), toQString(technique.name)));
    }
    QString score;
    const auto& contributions = result_->risk.contributions;
    if (static_cast<std::size_t>(row) < contributions.size()) {
        const ScoreContribution& c = contributions[static_cast<std::size_t>(row)];
        score = c.counted ? tr("Adds %1 points to the score.").arg(c.points, 0, 'f', 1)
                          : tr("Not counted: correlated with %1, which represents the same "
                               "behavior.")
                                .arg(toQString(c.correlatedWith));
    }

    QString text = QStringLiteral("%1\n%2 severity, %3 confidence    [%4]\n\n")
                       .arg(toQString(finding.title), severityText(finding.severity),
                            confidenceText(finding.confidence), toQString(finding.ruleId));
    text += section(tr("What was found"), toQString(finding.description));
    text += section(tr("Why it matters"), toQString(finding.explanation));
    text += section(tr("Limitations"), toQString(finding.limitations));
    text += section(tr("MITRE ATT&CK"), attack.join(QLatin1Char('\n')));
    text += section(tr("Next step"), toQString(finding.nextStep));
    text += section(tr("Scoring"), score);
    details_->setPlainText(text.trimmed());

    for (const Evidence& item : finding.evidence) {
        QString line = toQString(item.description);
        if (item.fileOffset) {
            line += QStringLiteral("  @ %1").arg(hex(*item.fileOffset));
        }
        auto* entry = new QListWidgetItem(line, evidence_);
        entry->setToolTip(toQString(item.location));
    }
}

} // namespace sectoryn::ui
