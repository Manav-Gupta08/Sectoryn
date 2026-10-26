#pragma once

#include "ui/AnalysisPanel.hpp"

class QComboBox;
class QLabel;
class QLineEdit;
class QListWidget;
class QPlainTextEdit;
class QTableView;

namespace sectoryn::ui {

class FindingFilterModel;
class FindingTableModel;

// All findings with severity and text filters. Selecting one shows its full explanation;
// activating an evidence entry asks the workspace to show where it came from.
class FindingsPanel final : public AnalysisPanel {
    Q_OBJECT

public:
    explicit FindingsPanel(QWidget* parent = nullptr);

    [[nodiscard]] QString title() const override { return tr("Findings"); }
    void showResult(const SharedResult& result) override;
    void clear() override;

private:
    void showFinding(int row);

    SharedResult result_;
    FindingTableModel* model_;
    FindingFilterModel* filter_;
    QLineEdit* search_;
    QComboBox* minimumSeverity_;
    QTableView* table_;
    QPlainTextEdit* details_;
    QListWidget* evidence_;
    QLabel* evidenceHint_;
    int currentFinding_ = -1;
};

} // namespace sectoryn::ui
