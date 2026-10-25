#include "ui/ImportsView.hpp"

#include "ui/Formatting.hpp"
#include "ui/models/ImportTableModel.hpp"

#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QRegularExpression>
#include <QSortFilterProxyModel>
#include <QSplitter>
#include <QTableView>
#include <QVBoxLayout>

namespace sectoryn::ui {

ImportsView::ImportsView(QWidget* parent)
    : AnalysisPanel(parent)
    , model_(new ImportTableModel(this))
    , byModule_(new QSortFilterProxyModel(this))
    , byText_(new QSortFilterProxyModel(this))
    , modules_(new QListWidget(this))
    , search_(new QLineEdit(this))
    , table_(new QTableView(this))
    , status_(new QLabel(this)) {
    byModule_->setSourceModel(model_);
    byModule_->setFilterKeyColumn(ImportTableModel::ModuleColumn);
    byText_->setSourceModel(byModule_);
    byText_->setFilterKeyColumn(-1);
    byText_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    byText_->setSortRole(ImportTableModel::SortRole);

    search_->setPlaceholderText(tr("Filter by module or function name"));
    search_->setClearButtonEnabled(true);
    connect(search_, &QLineEdit::textChanged, byText_,
            &QSortFilterProxyModel::setFilterFixedString);

    modules_->setAccessibleName(tr("Imported modules"));
    connect(modules_, &QListWidget::currentRowChanged, this, &ImportsView::selectModule);

    table_->setModel(byText_);
    table_->setSortingEnabled(true);
    table_->sortByColumn(ImportTableModel::ModuleColumn, Qt::AscendingOrder);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->hide();
    // ResizeToContents samples a bounded number of rows, so it stays cheap for large tables.
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(ImportTableModel::FunctionColumn,
                                                     QHeaderView::Stretch);
    table_->setAccessibleName(tr("Imported functions"));

    status_->setTextFormat(Qt::PlainText);
    status_->setObjectName(QStringLiteral("mutedText"));
    status_->setWordWrap(true);

    auto* right = new QWidget(this);
    auto* rightLayout = new QVBoxLayout(right);
    rightLayout->setContentsMargins(0, 0, 0, 0);
    rightLayout->addWidget(search_);
    rightLayout->addWidget(table_, 1);
    rightLayout->addWidget(status_);

    auto* splitter = new QSplitter(Qt::Horizontal, this);
    splitter->addWidget(modules_);
    splitter->addWidget(right);
    splitter->setStretchFactor(0, 1);
    splitter->setStretchFactor(1, 3);
    setContent(splitter);
    clear();
}

void ImportsView::clear() {
    model_->setResult(nullptr);
    modules_->clear();
    showMessage(tr("Open a file to see its imports."));
}

void ImportsView::showResult(const SharedResult& result) {
    model_->setResult(result);
    modules_->clear();
    search_->clear();
    if (!result->pe) {
        showMessage(tr("No import information is available for this file."));
        return;
    }
    const ImportTable& imports = result->pe->imports;
    if (imports.modules.empty()) {
        showMessage(tr("The file imports nothing.\n\nImports: %1\nDelay imports: %2")
                        .arg(fieldStatusText(imports.status),
                             fieldStatusText(imports.delayStatus)));
        return;
    }

    modules_->addItem(tr("All modules (%1)").arg(model_->rowCount()));
    for (const ImportedModule& module : imports.modules) {
        QString label = QStringLiteral("%1 (%2)").arg(toQString(module.name)).arg(
            module.functions.size());
        if (module.delayLoaded) {
            label += tr(" - delay-loaded");
        }
        auto* item = new QListWidgetItem(label, modules_);
        item->setData(Qt::UserRole, toQString(module.name));
    }
    modules_->setCurrentRow(0);
    status_->setText(tr("Imports: %1. Delay imports: %2. Imports show what a program can call, "
                        "not what it does call.")
                         .arg(fieldStatusText(imports.status),
                              fieldStatusText(imports.delayStatus)));
    showContent();
}

void ImportsView::selectModule(int row) {
    if (row <= 0) {
        byModule_->setFilterRegularExpression(QString());
        return;
    }
    const QString name = modules_->item(row)->data(Qt::UserRole).toString();
    byModule_->setFilterRegularExpression(
        QRegularExpression(QStringLiteral("^%1$").arg(QRegularExpression::escape(name))));
}

bool ImportsView::reveal(const Evidence& evidence) {
    if (evidence.location != "import table" && evidence.location != "delay import table") {
        return false;
    }
    // Import evidence reads "MODULE!function (category)".
    const QString text = toQString(evidence.description);
    const qsizetype bang = text.indexOf(QLatin1Char('!'));
    const qsizetype paren = text.indexOf(QStringLiteral(" ("), bang);
    if (bang <= 0 || paren <= bang) {
        return false;
    }
    const int row = model_->findRow(QStringView(text).left(bang),
                                    QStringView(text).mid(bang + 1, paren - bang - 1));
    if (row < 0) {
        return false;
    }
    modules_->setCurrentRow(0);
    search_->clear();
    const QModelIndex index =
        byText_->mapFromSource(byModule_->mapFromSource(model_->index(row, 0)));
    table_->setCurrentIndex(index);
    table_->scrollTo(index);
    showContent();
    return true;
}

} // namespace sectoryn::ui
