#pragma once

#include "ui/AnalysisPanel.hpp"

#include <QFrame>
#include <QString>
#include <QStringList>

#include <array>
#include <cstddef>
#include <vector>

class QDragEnterEvent;
class QDragLeaveEvent;
class QDropEvent;
class QLabel;
class QListWidget;
class QMimeData;

namespace sectoryn::ui {

// Start page: a drop target, what has been analyzed in this session, and which optional
// services are active. It shows nothing that did not come from a real analysis.
class DashboardView final : public QWidget {
    Q_OBJECT

public:
    explicit DashboardView(QWidget* parent = nullptr);

    void addResult(const SharedResult& result);
    // One line per optional service, e.g. "Hash reputation: disabled".
    void setServiceStatus(const QStringList& lines);

Q_SIGNALS:
    void openRequested();
    void filesDropped(const QStringList& paths);
    void resultActivated(const sectoryn::ui::SharedResult& result);

protected:
    void dragEnterEvent(QDragEnterEvent* event) override;
    void dragLeaveEvent(QDragLeaveEvent* event) override;
    void dropEvent(QDropEvent* event) override;

private:
    void setDragActive(bool active);
    void refreshSummary();

    // Results can hold megabytes of strings, so only the most recent few are kept for reopening.
    static constexpr std::size_t kMaxRecent = 8;

    QFrame* dropZone_;
    QLabel* summary_;
    QLabel* services_;
    QListWidget* recent_;
    std::vector<SharedResult> results_;
    int analyzedCount_ = 0;
    std::array<int, 5> findingsBySeverity_{};
};

// Local files among the URLs of a drag-and-drop, in order.
[[nodiscard]] QStringList localFiles(const QMimeData* mime);

} // namespace sectoryn::ui
