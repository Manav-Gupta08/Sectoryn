#include "ui/EntropyPanel.hpp"

#include "detectors/rules/EntropyRule.hpp"
#include "ui/EntropyChart.hpp"
#include "ui/Formatting.hpp"

#include <QHeaderView>
#include <QLabel>
#include <QSplitter>
#include <QTableWidget>
#include <QVBoxLayout>

namespace sectoryn::ui {

namespace {

enum Column { RangeColumn, OffsetColumn, BytesColumn, EntropyColumn, NoteColumn, ColumnCount };

QString entropyText(const std::optional<double>& entropy) {
    return entropy ? QString::number(*entropy, 'f', 3) : QStringLiteral("-");
}

} // namespace

EntropyPanel::EntropyPanel(QWidget* parent)
    : AnalysisPanel(parent)
    , ranges_(new EntropyChart(this))
    , profile_(new EntropyChart(this))
    , values_(new QTableWidget(this))
    , note_(new QLabel(this)) {
    ranges_->setThreshold(rules::EntropyRule::kHighEntropy);
    ranges_->setAccessibleName(tr("Entropy per section"));
    profile_->setThreshold(rules::EntropyRule::kHighEntropy);
    profile_->setAccessibleName(tr("Entropy across the file"));

    values_->setColumnCount(ColumnCount);
    values_->setHorizontalHeaderLabels(
        {tr("Range"), tr("File offset"), tr("Bytes"), tr("Entropy"), tr("Note")});
    values_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    values_->setSelectionBehavior(QAbstractItemView::SelectRows);
    values_->setAlternatingRowColors(true);
    values_->verticalHeader()->hide();
    values_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    values_->horizontalHeader()->setStretchLastSection(true);
    values_->setAccessibleName(tr("Entropy values"));

    note_->setTextFormat(Qt::PlainText);
    note_->setObjectName(QStringLiteral("mutedText"));
    note_->setWordWrap(true);
    note_->setText(tr("Shannon entropy in bits per byte (0-8). The dashed line marks %1, the level "
                      "the rules treat as high. High entropy means compressed or encrypted data, "
                      "which is common in benign files too.")
                       .arg(rules::EntropyRule::kHighEntropy, 0, 'f', 1));

    auto* splitter = new QSplitter(Qt::Vertical, this);
    splitter->addWidget(ranges_);
    splitter->addWidget(profile_);
    splitter->addWidget(values_);

    auto* content = new QWidget(this);
    auto* layout = new QVBoxLayout(content);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(splitter, 1);
    layout->addWidget(note_);
    setContent(content);
    clear();
}

void EntropyPanel::clear() {
    ranges_->clear();
    profile_->clear();
    values_->setRowCount(0);
    showMessage(tr("Open a file to see its entropy."));
}

void EntropyPanel::showResult(const SharedResult& result) {
    if (!result->entropy) {
        clear();
        showMessage(result->pe ? tr("Entropy was not computed for this file.")
                               : tr("Entropy is only computed for PE files."));
        return;
    }
    const EntropyReport& report = *result->entropy;
    const PeImage& pe = *result->pe;

    std::vector<ChartBar> bars;
    values_->setRowCount(0);
    const auto addRow = [this](const QString& range, const QString& offset,
                               std::uint64_t bytes, const std::optional<double>& entropy,
                               const QString& note) {
        const int row = values_->rowCount();
        values_->insertRow(row);
        const QStringList cells{range, offset, QString::number(bytes), entropyText(entropy), note};
        for (int column = 0; column < ColumnCount; ++column) {
            auto* item = new QTableWidgetItem(cells[column]);
            if (column == BytesColumn || column == EntropyColumn) {
                item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            }
            values_->setItem(row, column, item);
        }
    };

    const double fileEntropy = report.file.entropy();
    bars.push_back({tr("File"), fileEntropy, tr("Whole file: %1").arg(fileEntropy, 0, 'f', 3)});
    addRow(tr("Whole file"), hex(0), report.file.total(), fileEntropy, QString());

    for (std::size_t i = 0; i < report.sections.size() && i < pe.sections.size(); ++i) {
        const RangeEntropy& range = report.sections[i];
        const QString name = toQString(pe.sections[i].name);
        const SectionAssessment& assessment = result->sections.sections[i];
        QString note;
        if (!range.entropy && range.bytes > 0) {
            note = tr("skipped to stay within the read budget");
        } else if (!range.entropy) {
            note = tr("no raw data in the file");
        } else if (range.bytes < rules::EntropyRule::kMinBytes) {
            note = tr("too small to judge");
        }
        bars.push_back({name, range.entropy,
                        range.entropy ? tr("%1: %2 over %3 bytes")
                                            .arg(name)
                                            .arg(*range.entropy, 0, 'f', 3)
                                            .arg(range.bytes)
                                      : tr("%1: %2").arg(name, note)});
        addRow(tr("Section %1 %2").arg(i).arg(name), hex(assessment.readableRange.offset),
               range.bytes, range.entropy, note);
    }

    if (pe.overlay.status.state == FieldState::Present) {
        bars.push_back({tr("Overlay"), report.overlay.entropy,
                        tr("Overlay: %1").arg(entropyText(report.overlay.entropy))});
        addRow(tr("Overlay"), hex(pe.overlay.fileOffset), report.overlay.bytes,
               report.overlay.entropy,
               pe.overlay.containsCertificateTable ? tr("contains the certificate table")
                                                   : QString());
    }

    ranges_->setBars(std::move(bars));
    profile_->setProfile(report.profile, report.file.total());
    showContent();
}

} // namespace sectoryn::ui
