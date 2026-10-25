#pragma once

#include "ui/AnalysisPanel.hpp"

#include <QAbstractTableModel>

namespace sectoryn::ui {

class ExportTableModel final : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column { OrdinalColumn, NameColumn, RvaColumn, ForwarderColumn, ColumnCount };
    static constexpr int SortRole = Qt::UserRole + 1;

    explicit ExportTableModel(QObject* parent = nullptr);

    void setResult(SharedResult result);

    [[nodiscard]] int rowCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] int columnCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role) const override;
    [[nodiscard]] QVariant headerData(int section, Qt::Orientation orientation,
                                      int role) const override;

private:
    SharedResult result_;
};

} // namespace sectoryn::ui
