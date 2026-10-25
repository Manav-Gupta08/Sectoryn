#pragma once

#include "ui/AnalysisPanel.hpp"

class QLabel;
class QLineEdit;
class QSortFilterProxyModel;
class QTableView;

namespace sectoryn::ui {

class ExportTableModel;

class ExportsView final : public AnalysisPanel {
    Q_OBJECT

public:
    explicit ExportsView(QWidget* parent = nullptr);

    [[nodiscard]] QString title() const override { return tr("Exports"); }
    void showResult(const SharedResult& result) override;
    void clear() override;

private:
    ExportTableModel* model_;
    QSortFilterProxyModel* proxy_;
    QLabel* summary_;
    QLineEdit* search_;
    QTableView* table_;
};

} // namespace sectoryn::ui
