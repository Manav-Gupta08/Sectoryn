#include "ui/models/SectionTableModel.hpp"

#include "analysis/SectionCharacteristics.hpp"
#include "detectors/rules/EntropyRule.hpp"
#include "ui/Formatting.hpp"

#include <QColor>

#include <utility>

namespace sectoryn::ui {

namespace {

constexpr int kEntropyDecimals = 3;

} // namespace

SectionTableModel::SectionTableModel(QObject* parent)
    : QAbstractTableModel(parent) {}

void SectionTableModel::setResult(SharedResult result) {
    beginResetModel();
    result_ = std::move(result);
    anomalyCounts_.clear();
    if (result_ && result_->pe) {
        anomalyCounts_.assign(result_->pe->sections.size(), 0);
        for (const SectionAnomaly& anomaly : result_->sections.anomalies) {
            if (anomaly.section < anomalyCounts_.size()) {
                ++anomalyCounts_[anomaly.section];
            }
        }
    }
    endResetModel();
}

int SectionTableModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid() || !result_ || !result_->pe) {
        return 0;
    }
    return static_cast<int>(result_->pe->sections.size());
}

int SectionTableModel::columnCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant SectionTableModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() >= rowCount()) {
        return {};
    }
    const int row = index.row();
    const int column = index.column();
    const auto r = static_cast<std::size_t>(row);

    switch (role) {
    case Qt::DisplayRole:
        return display(row, column);
    case SortRole:
        return sortValue(row, column);
    case Qt::TextAlignmentRole:
        return column == NameColumn || column == DataColumn || column == PermissionsColumn
                   ? (Qt::AlignLeft | Qt::AlignVCenter).toInt()
                   : (Qt::AlignRight | Qt::AlignVCenter).toInt();
    case Qt::ToolTipRole:
        if (column == PermissionsColumn) {
            QStringList flags;
            for (const std::string& flag :
                 describeSectionCharacteristics(result_->pe->sections[r].characteristics)) {
                flags.append(toQString(flag));
            }
            return flags.join(QLatin1Char('\n'));
        }
        return {};
    case Qt::ForegroundRole: {
        const SectionFlags& flags = result_->sections.sections[r].flags;
        if (column == PermissionsColumn && flags.write && flags.execute) {
            return severityColor(Severity::High);
        }
        if (column == AnomaliesColumn && anomalyCounts_[r] > 0) {
            return severityColor(Severity::Medium);
        }
        if (column == EntropyColumn && result_->entropy && r < result_->entropy->sections.size()) {
            const auto& entropy = result_->entropy->sections[r].entropy;
            if (entropy && *entropy >= rules::EntropyRule::kHighEntropy) {
                return severityColor(Severity::Medium);
            }
        }
        return {};
    }
    default:
        return {};
    }
}

QVariant SectionTableModel::display(int row, int column) const {
    const auto r = static_cast<std::size_t>(row);
    const Section& section = result_->pe->sections[r];
    const SectionAssessment& assessment = result_->sections.sections[r];
    switch (column) {
    case IndexColumn:
        return row;
    case NameColumn:
        return toQString(section.name);
    case VirtualAddressColumn:
        return hex(section.virtualAddress, 8);
    case VirtualSizeColumn:
        return hex(section.virtualSize, 8);
    case RawOffsetColumn:
        return hex(section.pointerToRawData, 8);
    case RawSizeColumn:
        return hex(section.sizeOfRawData, 8);
    case PermissionsColumn:
        return toQString(permissionString(assessment.flags));
    case EntropyColumn:
        if (result_->entropy && r < result_->entropy->sections.size() &&
            result_->entropy->sections[r].entropy) {
            return QString::number(*result_->entropy->sections[r].entropy, 'f', kEntropyDecimals);
        }
        return QStringLiteral("-");
    case DataColumn:
        return toQString(toString(assessment.availability));
    case AnomaliesColumn:
        return anomalyCounts_[r];
    default:
        return {};
    }
}

QVariant SectionTableModel::sortValue(int row, int column) const {
    const auto r = static_cast<std::size_t>(row);
    const Section& section = result_->pe->sections[r];
    switch (column) {
    case VirtualAddressColumn:
        return static_cast<qulonglong>(section.virtualAddress);
    case VirtualSizeColumn:
        return static_cast<qulonglong>(section.virtualSize);
    case RawOffsetColumn:
        return static_cast<qulonglong>(section.pointerToRawData);
    case RawSizeColumn:
        return static_cast<qulonglong>(section.sizeOfRawData);
    case EntropyColumn:
        if (result_->entropy && r < result_->entropy->sections.size()) {
            return result_->entropy->sections[r].entropy.value_or(-1.0);
        }
        return -1.0;
    default:
        return display(row, column);
    }
}

QVariant SectionTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return QAbstractTableModel::headerData(section, orientation, role);
    }
    switch (section) {
    case IndexColumn:
        return tr("#");
    case NameColumn:
        return tr("Name");
    case VirtualAddressColumn:
        return tr("Virtual address");
    case VirtualSizeColumn:
        return tr("Virtual size");
    case RawOffsetColumn:
        return tr("Raw offset");
    case RawSizeColumn:
        return tr("Raw size");
    case PermissionsColumn:
        return tr("Access");
    case EntropyColumn:
        return tr("Entropy");
    case DataColumn:
        return tr("Raw data");
    case AnomaliesColumn:
        return tr("Anomalies");
    default:
        return {};
    }
}

} // namespace sectoryn::ui
