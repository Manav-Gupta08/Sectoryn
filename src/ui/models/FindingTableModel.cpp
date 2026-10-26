#include "ui/models/FindingTableModel.hpp"

#include "ui/Formatting.hpp"

#include <utility>

namespace sectoryn::ui {

FindingTableModel::FindingTableModel(QObject* parent)
    : QAbstractTableModel(parent) {}

void FindingTableModel::setResult(SharedResult result) {
    beginResetModel();
    result_ = std::move(result);
    endResetModel();
}

int FindingTableModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() || !result_ ? 0 : static_cast<int>(result_->findings.size());
}

int FindingTableModel::columnCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : ColumnCount;
}

const ScoreContribution* FindingTableModel::contribution(std::size_t finding) const {
    const auto& contributions = result_->risk.contributions;
    return finding < contributions.size() && contributions[finding].findingIndex == finding
               ? &contributions[finding]
               : nullptr;
}

QVariant FindingTableModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() >= rowCount()) {
        return {};
    }
    const auto row = static_cast<std::size_t>(index.row());
    const Finding& finding = result_->findings[row];
    const ScoreContribution* score = contribution(row);

    switch (role) {
    case SeverityRole:
        return static_cast<int>(finding.severity);
    case SortRole:
        switch (index.column()) {
        case SeverityColumn:
            return static_cast<int>(finding.severity);
        case ConfidenceColumn:
            return static_cast<int>(finding.confidence);
        case EvidenceColumn:
            return static_cast<qulonglong>(finding.evidence.size());
        case ScoreColumn:
            return score != nullptr && score->counted ? score->points : 0.0;
        default:
            return data(index, Qt::DisplayRole);
        }
    case Qt::ForegroundRole:
        return index.column() == SeverityColumn ? QVariant(severityColor(finding.severity))
                                                : QVariant();
    case Qt::ToolTipRole:
        return index.column() == TitleColumn ? QVariant(toQString(finding.description))
                                             : QVariant();
    case Qt::DisplayRole:
        switch (index.column()) {
        case SeverityColumn:
            return severityText(finding.severity);
        case ConfidenceColumn:
            return confidenceText(finding.confidence);
        case TitleColumn:
            return toQString(finding.title);
        case RuleColumn:
            return toQString(finding.ruleId);
        case EvidenceColumn:
            return static_cast<qulonglong>(finding.evidence.size());
        case AttackColumn: {
            QStringList ids;
            for (const AttackTechnique& technique : finding.attack) {
                ids.append(toQString(technique.id));
            }
            return ids.join(QStringLiteral(", "));
        }
        case ScoreColumn:
            if (score == nullptr) {
                return {};
            }
            return score->counted ? QString::number(score->points, 'f', 1) : tr("correlated");
        default:
            return {};
        }
    default:
        return {};
    }
}

QVariant FindingTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return QAbstractTableModel::headerData(section, orientation, role);
    }
    switch (section) {
    case SeverityColumn:
        return tr("Severity");
    case ConfidenceColumn:
        return tr("Confidence");
    case TitleColumn:
        return tr("Finding");
    case RuleColumn:
        return tr("Rule");
    case EvidenceColumn:
        return tr("Evidence");
    case AttackColumn:
        // Header labels treat '&' as a mnemonic marker.
        return tr("ATT&&CK");
    case ScoreColumn:
        return tr("Points");
    default:
        return {};
    }
}

} // namespace sectoryn::ui
