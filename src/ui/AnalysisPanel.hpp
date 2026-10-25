#pragma once

#include "detectors/Finding.hpp"
#include "engine/AnalysisResult.hpp"

#include <QString>
#include <QWidget>

#include <memory>

class QLabel;
class QStackedLayout;

namespace sectoryn::ui {

using SharedResult = std::shared_ptr<const AnalysisResult>;

// One tab of the analysis workspace. Panels share the result read-only; none of them copies it.
// A panel without data for the current file shows the reason instead of an empty view.
class AnalysisPanel : public QWidget {
    Q_OBJECT

public:
    explicit AnalysisPanel(QWidget* parent = nullptr);

    [[nodiscard]] virtual QString title() const = 0;
    virtual void showResult(const SharedResult& result) = 0;
    virtual void clear() = 0;

    // Selects the item an evidence entry points at. Returns false if this panel has no such item.
    virtual bool reveal(const Evidence& evidence);

Q_SIGNALS:
    // Emitted when the user asks to see where a piece of evidence came from.
    void evidenceActivated(const sectoryn::Evidence& evidence);

protected:
    void setContent(QWidget* content);
    void showContent();
    void showMessage(const QString& message);

private:
    QStackedLayout* layout_;
    QLabel* message_;
};

} // namespace sectoryn::ui
