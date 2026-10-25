#include "ui/models/ExportTableModel.hpp"

#include "ui/Formatting.hpp"

#include <utility>

namespace sectoryn::ui {

ExportTableModel::ExportTableModel(QObject* parent)
    : QAbstractTableModel(parent) {}

void ExportTableModel::setResult(SharedResult result) {
    beginResetModel();
    result_ = std::move(result);
    endResetModel();
}

int ExportTableModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid() || !result_ || !result_->pe) {
        return 0;
    }
    return static_cast<int>(result_->pe->exports.functions.size());
}

int ExportTableModel::columnCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant ExportTableModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() >= rowCount()) {
        return {};
    }
    const ExportedFunction& function =
        result_->pe->exports.functions[static_cast<std::size_t>(index.row())];

    if (role == SortRole) {
        switch (index.column()) {
        case OrdinalColumn:
            return static_cast<qulonglong>(function.ordinal);
        case RvaColumn:
            return static_cast<qulonglong>(function.rva);
        default:
            return data(index, Qt::DisplayRole);
        }
    }
    if (role != Qt::DisplayRole) {
        return {};
    }
    switch (index.column()) {
    case OrdinalColumn:
        return static_cast<qulonglong>(function.ordinal);
    case NameColumn:
        return function.name.empty() ? tr("(no name)") : toQString(function.name);
    case RvaColumn:
        return hex(function.rva, 8);
    case ForwarderColumn:
        return function.forwarder ? toQString(*function.forwarder) : QString();
    default:
        return {};
    }
}

QVariant ExportTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return QAbstractTableModel::headerData(section, orientation, role);
    }
    switch (section) {
    case OrdinalColumn:
        return tr("Ordinal");
    case NameColumn:
        return tr("Name");
    case RvaColumn:
        return tr("RVA");
    case ForwarderColumn:
        return tr("Forwarded to");
    default:
        return {};
    }
}

} // namespace sectoryn::ui
