#pragma once

#include "ui/AnalysisPanel.hpp"

#include <QMainWindow>
#include <QString>

#include <vector>

class QCloseEvent;
class QDragEnterEvent;
class QDropEvent;
class QLabel;
class QMenu;
class QProgressBar;
class QPushButton;
class QStackedWidget;
class QTabWidget;

namespace sectoryn::ui {

class AnalysisController;
class DashboardView;

// Hosts the dashboard and the analysis workspace. The panels shown in the workspace and the
// entries of the Tools menu are supplied by the application, so new views can be added without
// changing this class.
class MainWindow final : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(AnalysisController& controller, QWidget* parent = nullptr);

    // Takes ownership. Panels appear as workspace tabs in the order they are added.
    void addPanel(AnalysisPanel* panel);
    [[nodiscard]] QMenu* toolsMenu() const noexcept { return toolsMenu_; }
    [[nodiscard]] DashboardView* dashboard() const noexcept { return dashboard_; }
    [[nodiscard]] SharedResult currentResult() const { return current_; }

public Q_SLOTS:
    void openFileDialog();
    void analyzeFile(const QString& path);
    void showResult(const sectoryn::ui::SharedResult& result);
    void showDashboard();

Q_SIGNALS:
    void resultShown(const sectoryn::ui::SharedResult& result);

protected:
    void closeEvent(QCloseEvent* event) override;
    void dragEnterEvent(QDragEnterEvent* event) override;
    void dropEvent(QDropEvent* event) override;

private:
    void createMenus();
    void createStatusBar();
    void setBusy(bool busy, const QString& message);
    void revealEvidence(const Evidence& evidence);

    AnalysisController& controller_;
    QStackedWidget* pages_;
    DashboardView* dashboard_;
    QTabWidget* workspace_;
    std::vector<AnalysisPanel*> panels_;
    QMenu* toolsMenu_ = nullptr;
    QLabel* status_ = nullptr;
    QProgressBar* progress_ = nullptr;
    QPushButton* cancel_ = nullptr;
    SharedResult current_;
    QString lastDirectory_;
};

} // namespace sectoryn::ui
