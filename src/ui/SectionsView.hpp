#pragma once

#include "ui/AnalysisPanel.hpp"

class QPlainTextEdit;
class QSortFilterProxyModel;
class QTableView;

namespace sectoryn::ui {

class SectionTableModel;

// Section table with the details of the selected section.
class SectionsView final : public AnalysisPanel {
    Q_OBJECT

public:
    explicit SectionsView(QWidget* parent = nullptr);

    [[nodiscard]] QString title() const override { return tr("Sections"); }
    void showResult(const SharedResult& result) override;
    void clear() override;
    bool reveal(const Evidence& evidence) override;

private:
    void showDetails(int section);

    SharedResult result_;
    SectionTableModel* model_;
    QSortFilterProxyModel* proxy_;
    QTableView* table_;
    QPlainTextEdit* details_;
};

} // namespace sectoryn::ui
