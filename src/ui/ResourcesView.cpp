#include "ui/ResourcesView.hpp"

#include "ui/Formatting.hpp"
#include "ui/models/ResourceTableModel.hpp"

#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QVBoxLayout>

#include <cstdint>
#include <numeric>

namespace sectoryn::ui {

ResourcesView::ResourcesView(QWidget* parent)
    : AnalysisPanel(parent)
    , model_(new ResourceTableModel(this))
    , proxy_(new QSortFilterProxyModel(this))
    , summary_(new QLabel(this))
    , search_(new QLineEdit(this))
    , table_(new QTableView(this)) {
    proxy_->setSourceModel(model_);
    proxy_->setFilterKeyColumn(-1);
    proxy_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxy_->setSortRole(ResourceTableModel::SortRole);

    summary_->setTextFormat(Qt::PlainText);
    summary_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    summary_->setWordWrap(true);
    search_->setPlaceholderText(tr("Filter resources"));
    search_->setClearButtonEnabled(true);
    connect(search_, &QLineEdit::textChanged, proxy_, &QSortFilterProxyModel::setFilterFixedString);

    table_->setModel(proxy_);
    table_->setSortingEnabled(true);
    table_->sortByColumn(ResourceTableModel::OffsetColumn, Qt::AscendingOrder);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->hide();
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setAccessibleName(tr("Resource entries"));

    auto* content = new QWidget(this);
    auto* layout = new QVBoxLayout(content);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(summary_);
    layout->addWidget(search_);
    layout->addWidget(table_, 1);
    setContent(content);
    clear();
}

void ResourcesView::clear() {
    model_->setResult(nullptr);
    showMessage(tr("Open a file to see its resources."));
}

void ResourcesView::showResult(const SharedResult& result) {
    model_->setResult(result);
    search_->clear();
    if (!result->pe) {
        showMessage(tr("No resource information is available for this file."));
        return;
    }
    const ResourceTable& resources = result->pe->resources;
    if (!resources.status.hasData()) {
        showMessage(resources.status.state == FieldState::Absent
                        ? tr("The file has no resources.")
                        : tr("The resource directory could not be read.\n\n%1")
                              .arg(fieldStatusText(resources.status)));
        return;
    }
    const std::uint64_t total =
        std::accumulate(resources.entries.begin(), resources.entries.end(), std::uint64_t{0},
                        [](std::uint64_t sum, const ResourceEntry& e) { return sum + e.size; });
    summary_->setText(tr("%1 entries in %2 directories, %3 of data.    Status: %4")
                          .arg(resources.entries.size())
                          .arg(resources.directoryCount)
                          .arg(byteSize(total), fieldStatusText(resources.status)));
    showContent();
}

} // namespace sectoryn::ui
