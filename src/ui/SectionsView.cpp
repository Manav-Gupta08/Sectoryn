#include "ui/SectionsView.hpp"

#include "analysis/SectionCharacteristics.hpp"
#include "ui/Formatting.hpp"
#include "ui/models/SectionTableModel.hpp"

#include <QHeaderView>
#include <QPlainTextEdit>
#include <QSortFilterProxyModel>
#include <QSplitter>
#include <QTableView>
#include <QVBoxLayout>

#include <charconv>

namespace sectoryn::ui {

namespace {

// Evidence locations for sections look like "section 3 '.text'".
std::optional<int> sectionIndexOf(const Evidence& evidence) {
    constexpr std::string_view kPrefix = "section ";
    const std::string_view location = evidence.location;
    if (!location.starts_with(kPrefix)) {
        return std::nullopt;
    }
    int index = -1;
    const char* begin = location.data() + kPrefix.size();
    const auto [end, error] = std::from_chars(begin, location.data() + location.size(), index);
    if (error != std::errc{} || end == begin) {
        return std::nullopt;
    }
    return index;
}

} // namespace

SectionsView::SectionsView(QWidget* parent)
    : AnalysisPanel(parent)
    , model_(new SectionTableModel(this))
    , proxy_(new QSortFilterProxyModel(this))
    , table_(new QTableView(this))
    , details_(new QPlainTextEdit(this)) {
    proxy_->setSourceModel(model_);
    proxy_->setSortRole(SectionTableModel::SortRole);

    table_->setModel(proxy_);
    table_->setSortingEnabled(true);
    table_->sortByColumn(SectionTableModel::IndexColumn, Qt::AscendingOrder);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->hide();
    // Section tables are small, so sizing every column to its contents is cheap.
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setAccessibleName(tr("Section table"));

    details_->setReadOnly(true);
    details_->setAccessibleName(tr("Section details"));

    connect(table_->selectionModel(), &QItemSelectionModel::currentRowChanged, this,
            [this](const QModelIndex& current) {
                if (current.isValid()) {
                    showDetails(proxy_->mapToSource(current).row());
                }
            });

    auto* splitter = new QSplitter(Qt::Vertical, this);
    splitter->addWidget(table_);
    splitter->addWidget(details_);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);
    setContent(splitter);
    clear();
}

void SectionsView::clear() {
    result_.reset();
    model_->setResult(nullptr);
    details_->clear();
    showMessage(tr("Open a file to see its sections."));
}

void SectionsView::showResult(const SharedResult& result) {
    result_ = result;
    model_->setResult(result);
    details_->clear();
    if (!result->pe) {
        showMessage(tr("No section table is available for this file."));
        return;
    }
    if (result->pe->sections.empty()) {
        showMessage(tr("The file has no sections.\n\n%1")
                        .arg(fieldStatusText(result->pe->sectionTable)));
        return;
    }
    table_->selectRow(0);
    showContent();
}

bool SectionsView::reveal(const Evidence& evidence) {
    const std::optional<int> index = sectionIndexOf(evidence);
    if (!index || *index < 0 || *index >= model_->rowCount()) {
        return false;
    }
    const QModelIndex row = proxy_->mapFromSource(model_->index(*index, 0));
    table_->setCurrentIndex(row);
    table_->scrollTo(row);
    showContent();
    return true;
}

void SectionsView::showDetails(int section) {
    if (!result_ || !result_->pe || section < 0) {
        return;
    }
    const auto index = static_cast<std::size_t>(section);
    const Section& s = result_->pe->sections[index];
    const SectionAssessment& assessment = result_->sections.sections[index];

    QStringList lines;
    lines.append(tr("Section %1: %2").arg(section).arg(toQString(s.name)));
    lines.append(tr("Characteristics %1").arg(hex(s.characteristics, 8)));
    for (const std::string& flag : describeSectionCharacteristics(s.characteristics)) {
        lines.append(QStringLiteral("    %1").arg(toQString(flag)));
    }
    lines.append(tr("Raw data: %1, readable %2 at %3")
                     .arg(toQString(toString(assessment.availability)),
                          byteSize(assessment.readableRange.size),
                          hex(assessment.readableRange.offset)));
    if (result_->entropy && index < result_->entropy->sections.size()) {
        const RangeEntropy& entropy = result_->entropy->sections[index];
        lines.append(entropy.entropy
                         ? tr("Entropy %1 bits per byte over %2")
                               .arg(*entropy.entropy, 0, 'f', 3)
                               .arg(byteSize(entropy.bytes))
                         : tr("Entropy not measured"));
    }

    lines.append(QString());
    lines.append(tr("Anomalies:"));
    bool any = false;
    for (const SectionAnomaly& anomaly : result_->sections.anomalies) {
        if (anomaly.section == index ||
            (anomaly.otherSection && *anomaly.otherSection == index)) {
            lines.append(QStringLiteral("    %1 - %2")
                             .arg(toQString(toString(anomaly.kind)),
                                  toQString(anomaly.description)));
            any = true;
        }
    }
    if (!any) {
        lines.append(QStringLiteral("    %1").arg(tr("none")));
    }
    details_->setPlainText(lines.join(QLatin1Char('\n')));
}

} // namespace sectoryn::ui
