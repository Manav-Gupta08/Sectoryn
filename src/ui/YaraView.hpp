#pragma once

#include "ui/AnalysisPanel.hpp"

class QLabel;
class QTreeWidget;

namespace sectoryn::ui {

// Matches of the user's YARA rules with the offsets of the matching strings.
class YaraView final : public AnalysisPanel {
    Q_OBJECT

public:
    explicit YaraView(QWidget* parent = nullptr);

    [[nodiscard]] QString title() const override { return tr("YARA"); }
    void showResult(const SharedResult& result) override;
    void clear() override;

    // Describes the loaded rule set, or why none is loaded; shown above every result.
    void setRuleStatus(const QString& status);

private:
    QLabel* status_;
    QTreeWidget* tree_;
    QString ruleStatus_;
};

} // namespace sectoryn::ui
