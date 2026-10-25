#pragma once

#include "ui/AnalysisPanel.hpp"

#include <QAbstractTableModel>

namespace sectoryn::ui {

class ResourceTableModel final : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column {
        TypeColumn,
        NameColumn,
        LanguageColumn,
        SizeColumn,
        OffsetColumn,
        CodePageColumn,
        ColumnCount
    };
    static constexpr int SortRole = Qt::UserRole + 1;

    explicit ResourceTableModel(QObject* parent = nullptr);

    void setResult(SharedResult result);

    [[nodiscard]] int rowCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] int columnCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role) const override;
    [[nodiscard]] QVariant headerData(int section, Qt::Orientation orientation,
                                      int role) const override;

private:
    SharedResult result_;
};

// "RT_ICON (3)" for predefined types, the number alone for others.
[[nodiscard]] QString resourceTypeText(const ResourceEntry::Key& type);

} // namespace sectoryn::ui
