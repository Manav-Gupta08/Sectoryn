#pragma once

#include "ui/AnalysisPanel.hpp"

#include <QAbstractTableModel>

namespace sectoryn::ui {

class FindingTableModel final : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column {
        SeverityColumn,
        ConfidenceColumn,
        TitleColumn,
        RuleColumn,
        EvidenceColumn,
        AttackColumn,
        ScoreColumn,
        ColumnCount,
    };
    static constexpr int SortRole = Qt::UserRole + 1;
    static constexpr int SeverityRole = Qt::UserRole + 2;

    explicit FindingTableModel(QObject* parent = nullptr);

    void setResult(SharedResult result);

    [[nodiscard]] int rowCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] int columnCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role) const override;
    [[nodiscard]] QVariant headerData(int section, Qt::Orientation orientation,
                                      int role) const override;

private:
    [[nodiscard]] const ScoreContribution* contribution(std::size_t finding) const;

    SharedResult result_;
};

} // namespace sectoryn::ui
