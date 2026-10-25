#include "ui/models/ImportTableModel.hpp"

#include "ui/Formatting.hpp"

#include <utility>

namespace sectoryn::ui {

ImportTableModel::ImportTableModel(QObject* parent)
    : QAbstractTableModel(parent) {}

void ImportTableModel::setResult(SharedResult result) {
    beginResetModel();
    result_ = std::move(result);
    rows_.clear();
    if (result_ && result_->pe) {
        const std::vector<ImportedModule>& modules = result_->pe->imports.modules;
        for (std::size_t m = 0; m < modules.size(); ++m) {
            for (std::size_t f = 0; f < modules[m].functions.size(); ++f) {
                rows_.push_back({m, f});
            }
        }
    }
    endResetModel();
}

int ImportTableModel::findRow(QStringView module, QStringView function) const {
    for (std::size_t i = 0; i < rows_.size(); ++i) {
        const ImportedModule& m = result_->pe->imports.modules[rows_[i].module];
        const ImportedFunction& f = m.functions[rows_[i].function];
        if (toQString(m.name) == module && toQString(f.name) == function) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

int ImportTableModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : static_cast<int>(rows_.size());
}

int ImportTableModel::columnCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant ImportTableModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || static_cast<std::size_t>(index.row()) >= rows_.size()) {
        return {};
    }
    const Row& row = rows_[static_cast<std::size_t>(index.row())];
    const ImportedModule& module = result_->pe->imports.modules[row.module];
    const ImportedFunction& function = module.functions[row.function];

    if (role == ModuleIndexRole) {
        return static_cast<qulonglong>(row.module);
    }
    if (role == SortRole) {
        switch (index.column()) {
        case OrdinalColumn:
            return function.ordinal ? static_cast<int>(*function.ordinal) : -1;
        case HintColumn:
            return function.ordinal ? -1 : static_cast<int>(function.hint);
        default:
            return data(index, Qt::DisplayRole);
        }
    }
    if (role != Qt::DisplayRole) {
        return {};
    }
    switch (index.column()) {
    case ModuleColumn:
        return toQString(module.name);
    case FunctionColumn:
        return function.ordinal ? tr("(by ordinal)") : toQString(function.name);
    case OrdinalColumn:
        return function.ordinal ? QVariant(static_cast<int>(*function.ordinal)) : QVariant();
    case HintColumn:
        return function.ordinal ? QVariant() : QVariant(static_cast<int>(function.hint));
    case LoadColumn:
        return module.delayLoaded ? tr("Delay-loaded") : tr("At startup");
    default:
        return {};
    }
}

QVariant ImportTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return QAbstractTableModel::headerData(section, orientation, role);
    }
    switch (section) {
    case ModuleColumn:
        return tr("Module");
    case FunctionColumn:
        return tr("Function");
    case OrdinalColumn:
        return tr("Ordinal");
    case HintColumn:
        return tr("Hint");
    case LoadColumn:
        return tr("Loaded");
    default:
        return {};
    }
}

} // namespace sectoryn::ui
