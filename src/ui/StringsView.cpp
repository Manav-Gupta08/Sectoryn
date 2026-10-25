#include "ui/StringsView.hpp"

#include "ui/Formatting.hpp"
#include "ui/models/StringTableModel.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSaveFile>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QVBoxLayout>

#include <optional>

namespace sectoryn::ui {

class StringFilterModel final : public QSortFilterProxyModel {
public:
    using QSortFilterProxyModel::QSortFilterProxyModel;

    void setEncoding(std::optional<StringEncoding> encoding) {
        change([&] { encoding_ = encoding; });
    }
    void setIndicatorsOnly(bool only) {
        change([&] { indicatorsOnly_ = only; });
    }

protected:
    bool filterAcceptsRow(int row, const QModelIndex& parent) const override {
        const QModelIndex index = sourceModel()->index(row, 0, parent);
        if (indicatorsOnly_ && !index.data(StringTableModel::HasIndicatorRole).toBool()) {
            return false;
        }
        if (encoding_ &&
            index.data(StringTableModel::EncodingRole).toInt() != static_cast<int>(*encoding_)) {
            return false;
        }
        return QSortFilterProxyModel::filterAcceptsRow(row, parent);
    }

private:
    template <typename Change>
    void change(Change&& apply) {
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
        beginFilterChange();
        apply();
        endFilterChange(Direction::Rows);
#else
        apply();
        invalidateFilter();
#endif
    }

    std::optional<StringEncoding> encoding_;
    bool indicatorsOnly_ = false;
};

StringsView::StringsView(QWidget* parent)
    : AnalysisPanel(parent)
    , model_(new StringTableModel(this))
    , filter_(new StringFilterModel(this))
    , search_(new QLineEdit(this))
    , encoding_(new QComboBox(this))
    , indicatorsOnly_(new QCheckBox(tr("Only strings with indicators"), this))
    , table_(new QTableView(this))
    , count_(new QLabel(this)) {
    filter_->setSourceModel(model_);
    filter_->setFilterKeyColumn(StringTableModel::TextColumn);
    filter_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    filter_->setSortRole(StringTableModel::SortRole);

    search_->setPlaceholderText(tr("Search strings"));
    search_->setClearButtonEnabled(true);
    encoding_->addItem(tr("All encodings"));
    encoding_->addItem(toQString(toString(StringEncoding::Ascii)));
    encoding_->addItem(toQString(toString(StringEncoding::Utf16Le)));
    auto* exportButton = new QPushButton(tr("Export..."), this);
    exportButton->setToolTip(tr("Save the strings currently shown to a text file"));

    connect(search_, &QLineEdit::textChanged, this, [this](const QString& text) {
        filter_->setFilterFixedString(text);
        updateCount();
    });
    connect(encoding_, &QComboBox::currentIndexChanged, this, [this](int index) {
        filter_->setEncoding(index == 1   ? std::optional(StringEncoding::Ascii)
                             : index == 2 ? std::optional(StringEncoding::Utf16Le)
                                          : std::nullopt);
        updateCount();
    });
    connect(indicatorsOnly_, &QCheckBox::toggled, this, [this](bool only) {
        filter_->setIndicatorsOnly(only);
        updateCount();
    });
    connect(exportButton, &QPushButton::clicked, this, &StringsView::exportVisible);

    table_->setModel(filter_);
    table_->setSortingEnabled(true);
    table_->sortByColumn(StringTableModel::OffsetColumn, Qt::AscendingOrder);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setAlternatingRowColors(true);
    table_->setWordWrap(false);
    table_->verticalHeader()->hide();
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setAccessibleName(tr("Extracted strings"));

    count_->setTextFormat(Qt::PlainText);
    count_->setObjectName(QStringLiteral("mutedText"));
    count_->setWordWrap(true);

    auto* controls = new QHBoxLayout;
    controls->addWidget(search_, 1);
    controls->addWidget(encoding_);
    controls->addWidget(indicatorsOnly_);
    controls->addWidget(exportButton);

    auto* content = new QWidget(this);
    auto* layout = new QVBoxLayout(content);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addLayout(controls);
    layout->addWidget(table_, 1);
    layout->addWidget(count_);
    setContent(content);
    clear();
}

void StringsView::clear() {
    result_.reset();
    model_->setResult(nullptr);
    showMessage(tr("Open a file to see its strings."));
}

void StringsView::showResult(const SharedResult& result) {
    result_ = result;
    model_->setResult(result);
    if (!result->strings) {
        showMessage(result->pe ? tr("Strings were not extracted for this file.")
                               : tr("Strings are only extracted from PE files."));
        return;
    }
    updateCount();
    showContent();
}

bool StringsView::reveal(const Evidence& evidence) {
    if (evidence.location != "strings" || !evidence.fileOffset) {
        return false;
    }
    const int row = model_->rowContaining(*evidence.fileOffset);
    if (row < 0) {
        return false;
    }
    search_->clear();
    encoding_->setCurrentIndex(0);
    indicatorsOnly_->setChecked(false);
    const QModelIndex index = filter_->mapFromSource(model_->index(row, 0));
    table_->setCurrentIndex(index);
    table_->scrollTo(index, QAbstractItemView::PositionAtCenter);
    showContent();
    return true;
}

void StringsView::updateCount() {
    if (!result_ || !result_->strings) {
        count_->clear();
        return;
    }
    QString text = tr("Showing %1 of %2 strings.").arg(filter_->rowCount()).arg(model_->rowCount());
    if (result_->strings->limitReached) {
        text += tr(" Extraction stopped at a configured limit; the file contains more.");
    }
    text += tr(" Strings are shown as found and are never executed or opened.");
    count_->setText(text);
}

void StringsView::exportVisible() {
    const QString path = QFileDialog::getSaveFileName(this, tr("Export Strings"), QString(),
                                                      tr("Text files (*.txt);;All files (*)"));
    if (path.isEmpty()) {
        return;
    }
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Export failed"), file.errorString());
        return;
    }
    for (int row = 0; row < filter_->rowCount(); ++row) {
        const QModelIndex source = filter_->mapToSource(filter_->index(row, 0));
        const ExtractedString& string =
            result_->strings->strings[static_cast<std::size_t>(source.row())];
        const QString line = QStringLiteral("%1\t%2\t%3\n")
                                 .arg(hex(string.offset, 8), toQString(toString(string.encoding)),
                                      toQString(string.text));
        file.write(line.toUtf8());
    }
    if (!file.commit()) {
        QMessageBox::warning(this, tr("Export failed"), file.errorString());
    }
}

} // namespace sectoryn::ui
