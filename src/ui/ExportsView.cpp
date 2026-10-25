#include "ui/ExportsView.hpp"

#include "ui/Formatting.hpp"
#include "ui/models/ExportTableModel.hpp"

#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QVBoxLayout>

namespace sectoryn::ui {

ExportsView::ExportsView(QWidget* parent)
    : AnalysisPanel(parent)
    , model_(new ExportTableModel(this))
    , proxy_(new QSortFilterProxyModel(this))
    , summary_(new QLabel(this))
    , search_(new QLineEdit(this))
    , table_(new QTableView(this)) {
    proxy_->setSourceModel(model_);
    proxy_->setFilterKeyColumn(-1);
    proxy_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxy_->setSortRole(ExportTableModel::SortRole);

    summary_->setTextFormat(Qt::PlainText);
    summary_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    search_->setPlaceholderText(tr("Filter exports"));
    search_->setClearButtonEnabled(true);
    connect(search_, &QLineEdit::textChanged, proxy_,
            &QSortFilterProxyModel::setFilterFixedString);

    table_->setModel(proxy_);
    table_->setSortingEnabled(true);
    table_->sortByColumn(ExportTableModel::OrdinalColumn, Qt::AscendingOrder);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->hide();
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(ExportTableModel::NameColumn,
                                                     QHeaderView::Stretch);
    table_->setAccessibleName(tr("Exported functions"));

    auto* content = new QWidget(this);
    auto* layout = new QVBoxLayout(content);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(summary_);
    layout->addWidget(search_);
    layout->addWidget(table_, 1);
    setContent(content);
    clear();
}

void ExportsView::clear() {
    model_->setResult(nullptr);
    showMessage(tr("Open a file to see its exports."));
}

void ExportsView::showResult(const SharedResult& result) {
    model_->setResult(result);
    search_->clear();
    if (!result->pe) {
        showMessage(tr("No export information is available for this file."));
        return;
    }
    const ExportTable& exports = result->pe->exports;
    if (!exports.status.hasData()) {
        showMessage(exports.status.state == FieldState::Absent
                        ? tr("The file exports nothing.")
                        : tr("The export table could not be read.\n\n%1")
                              .arg(fieldStatusText(exports.status)));
        return;
    }
    summary_->setText(tr("Name: %1    Ordinal base: %2    Timestamp: %3    Status: %4")
                          .arg(exports.dllName.empty() ? tr("(none)") : toQString(exports.dllName))
                          .arg(exports.ordinalBase)
                          .arg(coffTimestamp(exports.timeDateStamp),
                               fieldStatusText(exports.status)));
    showContent();
}

} // namespace sectoryn::ui
