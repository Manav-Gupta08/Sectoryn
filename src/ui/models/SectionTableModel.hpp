#pragma once

#include "ui/AnalysisPanel.hpp"

#include <QAbstractTableModel>

#include <vector>

namespace sectoryn::ui {

class SectionTableModel final : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column {
        IndexColumn,
        NameColumn,
        VirtualAddressColumn,
        VirtualSizeColumn,
        RawOffsetColumn,
        RawSizeColumn,
        PermissionsColumn,
        EntropyColumn,
        DataColumn,
        AnomaliesColumn,
        ColumnCount,
    };
    // Unformatted value for sorting: numbers sort numerically, not as hex text.
    static constexpr int SortRole = Qt::UserRole + 1;

    explicit SectionTableModel(QObject* parent = nullptr);

    void setResult(SharedResult result);

    [[nodiscard]] int rowCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] int columnCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role) const override;
    [[nodiscard]] QVariant headerData(int section, Qt::Orientation orientation,
                                      int role) const override;

private:
    [[nodiscard]] QVariant display(int row, int column) const;
    [[nodiscard]] QVariant sortValue(int row, int column) const;

    SharedResult result_;
    std::vector<int> anomalyCounts_;
};

} // namespace sectoryn::ui
