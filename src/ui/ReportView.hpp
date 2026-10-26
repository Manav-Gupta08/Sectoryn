#pragma once

#include "reports/ReportCommon.hpp"
#include "ui/AnalysisPanel.hpp"

#include <QByteArray>

class QCheckBox;
class QComboBox;
class QLabel;
class QPlainTextEdit;
class QShowEvent;
class QStackedWidget;
class QTextBrowser;

namespace sectoryn::ui {

// Previews the HTML or JSON report for the current file and saves it. Reports are generated
// from the shared result when the tab is shown, and nothing is written until the user picks a
// destination.
class ReportView final : public AnalysisPanel {
    Q_OBJECT

public:
    explicit ReportView(QWidget* parent = nullptr);

    [[nodiscard]] QString title() const override { return tr("Report"); }
    void showResult(const SharedResult& result) override;
    void clear() override;

protected:
    void showEvent(QShowEvent* event) override;

private:
    [[nodiscard]] bool htmlSelected() const;
    [[nodiscard]] ReportOptions options() const;
    [[nodiscard]] QByteArray render() const;
    void refresh();
    void save();

    SharedResult result_;
    bool stale_ = false;
    QComboBox* format_;
    QCheckBox* includeStrings_;
    QCheckBox* includePath_;
    QStackedWidget* preview_;
    QTextBrowser* html_;
    QPlainTextEdit* json_;
    QLabel* note_;
};

} // namespace sectoryn::ui
