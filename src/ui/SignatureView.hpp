#pragma once

#include "ui/AnalysisPanel.hpp"

class QTreeWidget;

namespace sectoryn::ui {

// The certificate table as found in the file and, where the platform supports it, the result
// of verifying the Authenticode signature.
class SignatureView final : public AnalysisPanel {
    Q_OBJECT

public:
    explicit SignatureView(QWidget* parent = nullptr);

    [[nodiscard]] QString title() const override { return tr("Signature"); }
    void showResult(const SharedResult& result) override;
    void clear() override;

private:
    QTreeWidget* tree_;
};

// The result of the optional module with this ID, or null when it did not run.
[[nodiscard]] const EnrichmentResult* findEnrichment(const AnalysisResult& result,
                                                     std::string_view id);

} // namespace sectoryn::ui
