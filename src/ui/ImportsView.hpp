#pragma once

#include "ui/AnalysisPanel.hpp"

class QLabel;
class QLineEdit;
class QListWidget;
class QSortFilterProxyModel;
class QTableView;

namespace sectoryn::ui {

class ImportTableModel;

// Imported functions, filterable by module and by text.
class ImportsView final : public AnalysisPanel {
    Q_OBJECT

public:
    explicit ImportsView(QWidget* parent = nullptr);

    [[nodiscard]] QString title() const override { return tr("Imports"); }
    void showResult(const SharedResult& result) override;
    void clear() override;
    bool reveal(const Evidence& evidence) override;

private:
    void selectModule(int row);

    ImportTableModel* model_;
    QSortFilterProxyModel* byModule_;
    QSortFilterProxyModel* byText_;
    QListWidget* modules_;
    QLineEdit* search_;
    QTableView* table_;
    QLabel* status_;
};

} // namespace sectoryn::ui
