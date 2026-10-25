#pragma once

#include "ui/AnalysisPanel.hpp"

#include <QAbstractTableModel>

#include <vector>

namespace sectoryn::ui {

class StringTableModel final : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column { OffsetColumn, EncodingColumn, LengthColumn, IndicatorsColumn, TextColumn,
                  ColumnCount };
    static constexpr int SortRole = Qt::UserRole + 1;
    // True when at least one indicator was found in the string.
    static constexpr int HasIndicatorRole = Qt::UserRole + 2;
    static constexpr int EncodingRole = Qt::UserRole + 3;

    explicit StringTableModel(QObject* parent = nullptr);

    void setResult(SharedResult result);

    // Row of the string that contains `fileOffset`, or -1.
    [[nodiscard]] int rowContaining(std::uint64_t fileOffset) const;

    [[nodiscard]] int rowCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] int columnCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role) const override;
    [[nodiscard]] QVariant headerData(int section, Qt::Orientation orientation,
                                      int role) const override;

private:
    [[nodiscard]] const std::vector<ExtractedString>& strings() const;

    SharedResult result_;
    // Indicator kinds per string, joined for display.
    std::vector<QString> indicators_;
};

} // namespace sectoryn::ui
