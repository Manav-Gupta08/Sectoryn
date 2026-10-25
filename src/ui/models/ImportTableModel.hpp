#pragma once

#include "ui/AnalysisPanel.hpp"

#include <QAbstractTableModel>

#include <vector>

namespace sectoryn::ui {

// One row per imported function, regular and delay-loaded, with its module.
class ImportTableModel final : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column {
        ModuleColumn,
        FunctionColumn,
        OrdinalColumn,
        HintColumn,
        LoadColumn,
        ColumnCount,
    };
    // Index of the row's module in ImportTable::modules, for filtering by module.
    static constexpr int ModuleIndexRole = Qt::UserRole + 1;
    static constexpr int SortRole = Qt::UserRole + 2;

    explicit ImportTableModel(QObject* parent = nullptr);

    void setResult(SharedResult result);

    // Row of `module!function`, or -1.
    [[nodiscard]] int findRow(QStringView module, QStringView function) const;

    [[nodiscard]] int rowCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] int columnCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role) const override;
    [[nodiscard]] QVariant headerData(int section, Qt::Orientation orientation,
                                      int role) const override;

private:
    struct Row {
        std::size_t module;
        std::size_t function;
    };

    SharedResult result_;
    std::vector<Row> rows_;
};

} // namespace sectoryn::ui
