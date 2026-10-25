#pragma once

#include "ui/AnalysisPanel.hpp"

class QTreeWidget;
class QTreeWidgetItem;

namespace sectoryn::ui {

// Every header field as stored in the file, with decoded flags and structure availability.
class HeadersView final : public AnalysisPanel {
    Q_OBJECT

public:
    explicit HeadersView(QWidget* parent = nullptr);

    [[nodiscard]] QString title() const override { return tr("PE Headers"); }
    void showResult(const SharedResult& result) override;
    void clear() override;
    bool reveal(const Evidence& evidence) override;

private:
    QTreeWidget* tree_;
    QTreeWidgetItem* issues_ = nullptr;
};

} // namespace sectoryn::ui
