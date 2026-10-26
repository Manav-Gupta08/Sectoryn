#pragma once

#include "ui/AnalysisPanel.hpp"

class QLabel;
class QTableWidget;

namespace sectoryn::ui {

class EntropyChart;

// Entropy per range and across the file, with the exact values behind both charts.
class EntropyPanel final : public AnalysisPanel {
    Q_OBJECT

public:
    explicit EntropyPanel(QWidget* parent = nullptr);

    [[nodiscard]] QString title() const override { return tr("Entropy"); }
    void showResult(const SharedResult& result) override;
    void clear() override;

private:
    EntropyChart* ranges_;
    EntropyChart* profile_;
    QTableWidget* values_;
    QLabel* note_;
};

} // namespace sectoryn::ui
