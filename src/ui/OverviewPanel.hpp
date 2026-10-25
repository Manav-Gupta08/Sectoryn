#pragma once

#include "ui/AnalysisPanel.hpp"

class QFormLayout;
class QLabel;
class QPlainTextEdit;

namespace sectoryn::ui {

// Summary of one analysis: the file, its format, the triage outcome and how it was reached.
class OverviewPanel final : public AnalysisPanel {
    Q_OBJECT

public:
    explicit OverviewPanel(QWidget* parent = nullptr);

    [[nodiscard]] QString title() const override { return tr("Overview"); }
    void showResult(const SharedResult& result) override;
    void clear() override;

private:
    void addRow(const QString& label, const QString& value);

    QLabel* outcome_;
    QLabel* score_;
    QFormLayout* facts_;
    QPlainTextEdit* explanation_;
};

} // namespace sectoryn::ui
