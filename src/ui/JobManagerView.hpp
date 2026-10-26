#pragma once

#include "core/Result.hpp"
#include "engine/BatchManager.hpp"
#include "ui/AnalysisPanel.hpp"

#include <QStringList>
#include <QWidget>

#include <filesystem>
#include <memory>

class QCheckBox;
class QDragEnterEvent;
class QDropEvent;
class QLabel;
class QPushButton;
class QSortFilterProxyModel;
class QTableView;

namespace sectoryn::ui {

class JobTableModel;

// Queues many files for analysis and follows their progress. Jobs run on the batch manager's
// worker threads; their updates are applied here on the UI thread.
class JobManagerView final : public QWidget {
    Q_OBJECT

public:
    JobManagerView(std::shared_ptr<const AnalysisEngine> engine, BatchOptions options,
                   QWidget* parent = nullptr);
    // Cancels outstanding jobs and waits for the workers before the model goes away.
    ~JobManagerView() override;

    JobManagerView(const JobManagerView&) = delete;
    JobManagerView& operator=(const JobManagerView&) = delete;
    JobManagerView(JobManagerView&&) = delete;
    JobManagerView& operator=(JobManagerView&&) = delete;

    // Takes effect once no job is running.
    void configure(std::shared_ptr<const AnalysisEngine> engine, BatchOptions options);

    // Returns how many files were queued. Files beyond the queue limit are reported, not kept.
    int addFiles(const QStringList& paths);
    int addFolder(const QString& folder);

    // While set, JSON and HTML reports of every completed job are written to this folder.
    void setReportFolder(const QString& folder);
    // Writes one line per job; a path ending in .json gives JSON, anything else CSV.
    [[nodiscard]] Status exportSummary(const QString& path) const;

    [[nodiscard]] const JobTableModel& model() const noexcept { return *model_; }

public Q_SLOTS:
    void cancelAll();

Q_SIGNALS:
    void jobCompleted(const sectoryn::ui::SharedResult& result);
    void resultActivated(const sectoryn::ui::SharedResult& result);
    // A finished job whose result is no longer held in memory was opened.
    void reanalysisRequested(const QString& path);

protected:
    void dragEnterEvent(QDragEnterEvent* event) override;
    void dropEvent(QDropEvent* event) override;

private:
    [[nodiscard]] bool ensureManager();
    void apply(const JobUpdate& update);
    void openJob(int row);
    void cancelSelected();
    void chooseReportFolder(bool enabled);
    void chooseSummaryFile();
    void updateSummary();

    std::shared_ptr<const AnalysisEngine> engine_;
    BatchOptions options_;
    bool reconfigure_ = false;
    std::unique_ptr<BatchManager> manager_;

    JobTableModel* model_;
    QSortFilterProxyModel* sorted_;
    QTableView* table_;
    QLabel* summary_;
    QPushButton* cancelSelected_;
    QPushButton* cancelAll_;
    QCheckBox* saveReports_;
    QString reportFolder_;
    QString lastDirectory_;
    // Explains the most recent files that could not be added.
    QString notice_;
};

} // namespace sectoryn::ui
