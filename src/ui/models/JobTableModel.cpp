#include "ui/models/JobTableModel.hpp"

#include "ui/Formatting.hpp"

#include <QFileInfo>

#include <algorithm>

namespace sectoryn::ui {

namespace {

QString stateText(JobState state) {
    switch (state) {
    case JobState::Queued:
        return JobTableModel::tr("Queued");
    case JobState::Running:
        return JobTableModel::tr("Running");
    case JobState::Completed:
        return JobTableModel::tr("Completed");
    case JobState::Duplicate:
        return JobTableModel::tr("Duplicate");
    case JobState::Failed:
        return JobTableModel::tr("Failed");
    case JobState::Cancelled:
        return JobTableModel::tr("Cancelled");
    }
    return JobTableModel::tr("Unknown");
}

} // namespace

JobTableModel::JobTableModel(QObject* parent)
    : QAbstractTableModel(parent) {}

void JobTableModel::apply(const JobUpdate& update) {
    auto found = index_.find(update.id);
    if (found == index_.end()) {
        const auto row = static_cast<int>(rows_.size());
        beginInsertRows({}, row, row);
        rows_.push_back({.id = update.id,
                         .path = QString::fromStdU16String(update.path.u16string())});
        found = index_.emplace(update.id, rows_.size() - 1).first;
        endInsertRows();
    }

    JobRow& job = rows_[found->second];
    job.state = update.state;
    job.message = toQString(update.message);
    job.duplicateOf = update.duplicateOf;
    if (!update.sha256.empty()) {
        job.sha256 = update.sha256;
    }
    if (update.result) {
        job.outcome = update.result->risk.outcome;
        job.score = update.result->risk.score;
        job.findings = update.result->findings.size();
        job.result = update.result;
        retain(job.id);
    }
    const auto row = static_cast<int>(found->second);
    Q_EMIT dataChanged(index(row, 0), index(row, ColumnCount - 1));
}

void JobTableModel::retain(JobId id) {
    retained_.push_back(id);
    while (retained_.size() > kMaxRetainedResults) {
        if (const auto it = index_.find(retained_.front()); it != index_.end()) {
            rows_[it->second].result.reset();
        }
        retained_.pop_front();
    }
}

void JobTableModel::removeFinished() {
    beginResetModel();
    std::erase_if(rows_, [](const JobRow& job) { return isFinal(job.state); });
    reindex();
    endResetModel();
}

void JobTableModel::reindex() {
    index_.clear();
    for (std::size_t i = 0; i < rows_.size(); ++i) {
        index_.emplace(rows_[i].id, i);
    }
    std::erase_if(retained_, [this](JobId id) { return !index_.contains(id); });
}

const JobRow* JobTableModel::jobAt(int row) const {
    return row >= 0 && row < rowCount() ? &rows_[static_cast<std::size_t>(row)] : nullptr;
}

std::size_t JobTableModel::count(JobState state) const {
    return static_cast<std::size_t>(
        std::ranges::count(rows_, state, &JobRow::state));
}

int JobTableModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : static_cast<int>(rows_.size());
}

int JobTableModel::columnCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant JobTableModel::data(const QModelIndex& index, int role) const {
    const JobRow* job = jobAt(index.row());
    if (job == nullptr || index.column() >= ColumnCount) {
        return {};
    }
    const bool scored = job->outcome && *job->outcome != TriageOutcome::UnsupportedOrInvalid;

    if (role == SortRole) {
        switch (index.column()) {
        case StateColumn:
            return static_cast<int>(job->state);
        case OutcomeColumn:
            return job->outcome ? static_cast<int>(*job->outcome) : -1;
        case ScoreColumn:
            return scored ? job->score : -1.0;
        case FindingsColumn:
            return static_cast<qulonglong>(job->findings);
        default:
            return data(index, Qt::DisplayRole);
        }
    }
    if (role == Qt::ToolTipRole) {
        return index.column() == FileColumn ? job->path : QVariant();
    }
    if (role != Qt::DisplayRole) {
        return {};
    }
    switch (index.column()) {
    case FileColumn:
        return QFileInfo(job->path).fileName();
    case StateColumn:
        return stateText(job->state);
    case OutcomeColumn:
        return job->outcome ? toQString(toString(*job->outcome)) : QString();
    case ScoreColumn:
        return scored ? QString::number(job->score, 'f', 1) : QString();
    case FindingsColumn:
        return job->outcome ? QVariant(static_cast<qulonglong>(job->findings)) : QVariant();
    case DetailColumn:
        if (job->duplicateOf) {
            return tr("Same content as job %1").arg(*job->duplicateOf);
        }
        return job->message;
    default:
        return {};
    }
}

QVariant JobTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return QAbstractTableModel::headerData(section, orientation, role);
    }
    switch (section) {
    case FileColumn:
        return tr("File");
    case StateColumn:
        return tr("State");
    case OutcomeColumn:
        return tr("Outcome");
    case ScoreColumn:
        return tr("Score");
    case FindingsColumn:
        return tr("Findings");
    case DetailColumn:
        return tr("Details");
    default:
        return {};
    }
}

} // namespace sectoryn::ui
