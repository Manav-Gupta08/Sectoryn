#pragma once

#include "engine/BatchManager.hpp"
#include "ui/AnalysisPanel.hpp"

#include <QAbstractTableModel>
#include <QString>

#include <cstddef>
#include <deque>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace sectoryn::ui {

struct JobRow {
    JobId id = 0;
    QString path{};
    JobState state = JobState::Queued;
    QString message{};
    std::string sha256{};
    std::optional<JobId> duplicateOf{};
    std::optional<TriageOutcome> outcome{};
    double score = 0.0;
    std::size_t findings = 0;
    // Only the most recent results are kept; see JobTableModel::kMaxRetainedResults.
    SharedResult result{};
};

// One row per batch job, updated as the job moves through its states.
class JobTableModel final : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column {
        FileColumn,
        StateColumn,
        OutcomeColumn,
        ScoreColumn,
        FindingsColumn,
        DetailColumn,
        ColumnCount,
    };
    static constexpr int SortRole = Qt::UserRole + 1;

    // Each result can hold megabytes of strings, so a large batch keeps only the latest few in
    // memory. Older rows keep their summary and can be analyzed again on request.
    static constexpr std::size_t kMaxRetainedResults = 16;

    explicit JobTableModel(QObject* parent = nullptr);

    void apply(const JobUpdate& update);
    void removeFinished();

    [[nodiscard]] const JobRow* jobAt(int row) const;
    [[nodiscard]] const std::vector<JobRow>& jobs() const noexcept { return rows_; }
    [[nodiscard]] std::size_t count(JobState state) const;

    [[nodiscard]] int rowCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] int columnCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role) const override;
    [[nodiscard]] QVariant headerData(int section, Qt::Orientation orientation,
                                      int role) const override;

private:
    void retain(JobId id);
    void reindex();

    std::vector<JobRow> rows_;
    std::unordered_map<JobId, std::size_t> index_;
    std::deque<JobId> retained_;
};

} // namespace sectoryn::ui
