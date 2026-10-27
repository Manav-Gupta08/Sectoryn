#include "ui/YaraView.hpp"

#include "ui/Formatting.hpp"
#include "ui/SignatureView.hpp"

#include <QHeaderView>
#include <QLabel>
#include <QTreeWidget>
#include <QVBoxLayout>

namespace sectoryn::ui {

YaraView::YaraView(QWidget* parent)
    : AnalysisPanel(parent)
    , status_(new QLabel(this))
    , tree_(new QTreeWidget(this))
    , ruleStatus_(tr("YARA scanning is not configured.")) {
    status_->setTextFormat(Qt::PlainText);
    status_->setWordWrap(true);
    status_->setTextInteractionFlags(Qt::TextSelectableByMouse);

    tree_->setColumnCount(3);
    tree_->setHeaderLabels({tr("Rule / string"), tr("Detail"), tr("File offset")});
    tree_->setAlternatingRowColors(true);
    tree_->setUniformRowHeights(true);
    tree_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    tree_->setAccessibleName(tr("YARA matches"));
    connect(tree_, &QTreeWidget::itemActivated, this, [this](QTreeWidgetItem* item) {
        const QVariant offset = item->data(2, Qt::UserRole);
        if (offset.isValid()) {
            Q_EMIT evidenceActivated({.description = item->text(1).toStdString(),
                                      .fileOffset = offset.toULongLong(),
                                      .location = "YARA match"});
        }
    });

    auto* content = new QWidget(this);
    auto* layout = new QVBoxLayout(content);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(status_);
    layout->addWidget(tree_, 1);
    setContent(content);
    clear();
}

void YaraView::setRuleStatus(const QString& status) {
    ruleStatus_ = status;
    status_->setText(status);
}

void YaraView::clear() {
    tree_->clear();
    showMessage(tr("Open a file to see YARA matches.\n\n%1").arg(ruleStatus_));
}

void YaraView::showResult(const SharedResult& result) {
    tree_->clear();
    const EnrichmentResult* yara = findEnrichment(*result, "yara");
    if (yara == nullptr) {
        showMessage(result->pe ? tr("No YARA scan was run.\n\n%1").arg(ruleStatus_)
                               : tr("YARA scans run only on files that parse as PE."));
        return;
    }

    QStringList summary{ruleStatus_, tr("Scan: %1").arg(fieldStatusText(yara->status))};
    for (const EnrichmentProperty& property : yara->properties) {
        summary.append(
            QStringLiteral("%1: %2").arg(toQString(property.name), toQString(property.value)));
    }
    status_->setText(summary.join(QStringLiteral("    ")));

    for (const Finding& finding : result->findings) {
        if (!finding.ruleId.starts_with("yara.")) {
            continue;
        }
        auto* rule = new QTreeWidgetItem(
            tree_, {toQString(finding.ruleId.substr(5)),
                    QStringLiteral("[%1] %2").arg(severityText(finding.severity),
                                                  toQString(finding.description)),
                    QString()});
        rule->setForeground(0, severityColor(finding.severity));
        for (const Evidence& evidence : finding.evidence) {
            auto* item = new QTreeWidgetItem(
                rule, {toQString(evidence.location), toQString(evidence.description),
                       evidence.fileOffset ? hex(*evidence.fileOffset, 8) : QString()});
            if (evidence.fileOffset) {
                item->setData(2, Qt::UserRole, static_cast<qulonglong>(*evidence.fileOffset));
            }
        }
    }
    if (tree_->topLevelItemCount() == 0) {
        new QTreeWidgetItem(tree_, {tr("No rule matched."), QString(), QString()});
    }
    tree_->expandAll();
    showContent();
}

} // namespace sectoryn::ui
