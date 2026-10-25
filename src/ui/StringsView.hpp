#pragma once

#include "ui/AnalysisPanel.hpp"

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QTableView;

namespace sectoryn::ui {

class StringFilterModel;
class StringTableModel;

// Extracted strings with search, encoding and indicator filters, and export of the visible rows.
class StringsView final : public AnalysisPanel {
    Q_OBJECT

public:
    explicit StringsView(QWidget* parent = nullptr);

    [[nodiscard]] QString title() const override { return tr("Strings"); }
    void showResult(const SharedResult& result) override;
    void clear() override;
    bool reveal(const Evidence& evidence) override;

private:
    void exportVisible();
    void updateCount();

    SharedResult result_;
    StringTableModel* model_;
    StringFilterModel* filter_;
    QLineEdit* search_;
    QComboBox* encoding_;
    QCheckBox* indicatorsOnly_;
    QTableView* table_;
    QLabel* count_;
};

} // namespace sectoryn::ui
