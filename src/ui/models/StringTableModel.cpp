#include "ui/models/StringTableModel.hpp"

#include "ui/Formatting.hpp"

#include <algorithm>
#include <utility>

namespace sectoryn::ui {

namespace {

// Long strings are shortened in the table; the full text is in the tooltip.
constexpr qsizetype kMaxDisplayChars = 300;

std::uint64_t byteLength(const ExtractedString& string) {
    const std::uint64_t unit = string.encoding == StringEncoding::Utf16Le ? 2 : 1;
    return string.text.size() * unit;
}

} // namespace

StringTableModel::StringTableModel(QObject* parent)
    : QAbstractTableModel(parent) {}

void StringTableModel::setResult(SharedResult result) {
    beginResetModel();
    result_ = std::move(result);
    indicators_.assign(strings().size(), QString());
    if (result_) {
        for (const Indicator& indicator : result_->indicators) {
            if (indicator.stringIndex >= indicators_.size()) {
                continue;
            }
            QString& kinds = indicators_[indicator.stringIndex];
            const QString kind = toQString(toString(indicator.kind));
            if (!kinds.contains(kind)) {
                kinds += kinds.isEmpty() ? kind : QStringLiteral(", ") + kind;
            }
        }
    }
    endResetModel();
}

const std::vector<ExtractedString>& StringTableModel::strings() const {
    static const std::vector<ExtractedString> kEmpty;
    return result_ && result_->strings ? result_->strings->strings : kEmpty;
}

int StringTableModel::rowContaining(std::uint64_t fileOffset) const {
    // Strings are ordered by offset. ASCII and UTF-16 runs from different lanes can interleave,
    // so a few strings starting before the offset are checked, nearest first.
    constexpr int kCandidates = 8;
    const std::vector<ExtractedString>& all = strings();
    auto it = std::ranges::upper_bound(all, fileOffset, {}, &ExtractedString::offset);
    for (int checked = 0; it != all.begin() && checked < kCandidates; ++checked) {
        --it;
        if (fileOffset - it->offset < byteLength(*it)) {
            return static_cast<int>(std::distance(all.begin(), it));
        }
    }
    return -1;
}

int StringTableModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : static_cast<int>(strings().size());
}

int StringTableModel::columnCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant StringTableModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() >= rowCount()) {
        return {};
    }
    const auto row = static_cast<std::size_t>(index.row());
    const ExtractedString& string = strings()[row];

    switch (role) {
    case HasIndicatorRole:
        return !indicators_[row].isEmpty();
    case EncodingRole:
        return static_cast<int>(string.encoding);
    case SortRole:
        switch (index.column()) {
        case OffsetColumn:
            return static_cast<qulonglong>(string.offset);
        case LengthColumn:
            return static_cast<qulonglong>(string.text.size());
        default:
            return data(index, Qt::DisplayRole);
        }
    case Qt::ToolTipRole:
        return index.column() == TextColumn && string.text.size() > kMaxDisplayChars
                   ? QVariant(toQString(string.text))
                   : QVariant();
    case Qt::DisplayRole:
        switch (index.column()) {
        case OffsetColumn:
            return hex(string.offset, 8);
        case EncodingColumn:
            return toQString(toString(string.encoding));
        case LengthColumn:
            return string.truncated ? tr("%1+").arg(string.text.size())
                                    : QString::number(string.text.size());
        case IndicatorsColumn:
            return indicators_[row];
        case TextColumn: {
            QString text = toQString(string.text);
            if (text.size() > kMaxDisplayChars) {
                text = text.left(kMaxDisplayChars) + QStringLiteral("...");
            }
            return text;
        }
        default:
            return {};
        }
    default:
        return {};
    }
}

QVariant StringTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return QAbstractTableModel::headerData(section, orientation, role);
    }
    switch (section) {
    case OffsetColumn:
        return tr("Offset");
    case EncodingColumn:
        return tr("Encoding");
    case LengthColumn:
        return tr("Length");
    case IndicatorsColumn:
        return tr("Indicators");
    case TextColumn:
        return tr("Text");
    default:
        return {};
    }
}

} // namespace sectoryn::ui
