#pragma once

#include "ui/AnalysisPanel.hpp"

class QLabel;
class QLineEdit;
class QSortFilterProxyModel;
class QTableView;

namespace sectoryn::ui {

class ResourceTableModel;

// Resource directory entries with their type, name, language and location in the file.
// Resource data is listed, never opened or rendered.
class ResourcesView final : public AnalysisPanel {
    Q_OBJECT

public:
    explicit ResourcesView(QWidget* parent = nullptr);

    [[nodiscard]] QString title() const override { return tr("Resources"); }
    void showResult(const SharedResult& result) override;
    void clear() override;

private:
    ResourceTableModel* model_;
    QSortFilterProxyModel* proxy_;
    QLabel* summary_;
    QLineEdit* search_;
    QTableView* table_;
};

} // namespace sectoryn::ui
