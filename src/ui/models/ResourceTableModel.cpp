#include "ui/models/ResourceTableModel.hpp"

#include "ui/Formatting.hpp"

#include <array>
#include <string_view>
#include <utility>

namespace sectoryn::ui {

namespace {

// Predefined resource types from winuser.h, indexed by ID.
constexpr std::array<std::string_view, 25> kTypeNames = {
    "",          "RT_CURSOR",       "RT_BITMAP",       "RT_ICON", "RT_MENU",
    "RT_DIALOG", "RT_STRING",       "RT_FONTDIR",      "RT_FONT", "RT_ACCELERATOR",
    "RT_RCDATA", "RT_MESSAGETABLE", "RT_GROUP_CURSOR", "",        "RT_GROUP_ICON",
    "",          "RT_VERSION",      "RT_DLGINCLUDE",   "",        "RT_PLUGPLAY",
    "RT_VXD",    "RT_ANICURSOR",    "RT_ANIICON",      "RT_HTML", "RT_MANIFEST",
};

QString keyText(const ResourceEntry::Key& key) {
    if (key.id) {
        return QString::number(*key.id);
    }
    return toQString(key.name);
}

} // namespace

QString resourceTypeText(const ResourceEntry::Key& type) {
    if (type.id && *type.id < kTypeNames.size() && !kTypeNames[*type.id].empty()) {
        return QStringLiteral("%1 (%2)").arg(toQString(kTypeNames[*type.id])).arg(*type.id);
    }
    return keyText(type);
}

ResourceTableModel::ResourceTableModel(QObject* parent)
    : QAbstractTableModel(parent) {}

void ResourceTableModel::setResult(SharedResult result) {
    beginResetModel();
    result_ = std::move(result);
    endResetModel();
}

int ResourceTableModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid() || !result_ || !result_->pe) {
        return 0;
    }
    return static_cast<int>(result_->pe->resources.entries.size());
}

int ResourceTableModel::columnCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant ResourceTableModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() >= rowCount()) {
        return {};
    }
    const ResourceEntry& entry =
        result_->pe->resources.entries[static_cast<std::size_t>(index.row())];

    if (role == SortRole) {
        switch (index.column()) {
        case SizeColumn:
            return static_cast<qulonglong>(entry.size);
        case OffsetColumn:
            return static_cast<qulonglong>(entry.fileOffset);
        case CodePageColumn:
            return static_cast<qulonglong>(entry.codePage);
        default:
            return data(index, Qt::DisplayRole);
        }
    }
    if (role == Qt::TextAlignmentRole && index.column() >= SizeColumn) {
        return QVariant::fromValue(Qt::AlignRight | Qt::AlignVCenter);
    }
    if (role != Qt::DisplayRole) {
        return {};
    }
    switch (index.column()) {
    case TypeColumn:
        return resourceTypeText(entry.type);
    case NameColumn:
        return keyText(entry.name);
    case LanguageColumn:
        return entry.language.id ? hex(*entry.language.id, 4) : toQString(entry.language.name);
    case SizeColumn:
        return byteSize(entry.size);
    case OffsetColumn:
        return hex(entry.fileOffset, 8);
    case CodePageColumn:
        return static_cast<qulonglong>(entry.codePage);
    default:
        return {};
    }
}

QVariant ResourceTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return QAbstractTableModel::headerData(section, orientation, role);
    }
    switch (section) {
    case TypeColumn:
        return tr("Type");
    case NameColumn:
        return tr("Name / ID");
    case LanguageColumn:
        return tr("Language");
    case SizeColumn:
        return tr("Size");
    case OffsetColumn:
        return tr("File offset");
    case CodePageColumn:
        return tr("Code page");
    default:
        return {};
    }
}

} // namespace sectoryn::ui
