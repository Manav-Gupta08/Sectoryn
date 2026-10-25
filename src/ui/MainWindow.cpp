#include "ui/MainWindow.hpp"

#include "ui/AnalysisController.hpp"
#include "ui/DashboardView.hpp"
#include "ui/Formatting.hpp"

#include <QAction>
#include <QApplication>
#include <QCloseEvent>
#include <QDragEnterEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QKeySequence>
#include <QLabel>
#include <QMenuBar>
#include <QMessageBox>
#include <QMimeData>
#include <QProgressBar>
#include <QPushButton>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTabWidget>

namespace sectoryn::ui {

namespace {

constexpr int kDefaultWidth = 1280;
constexpr int kDefaultHeight = 800;

int stageCount() {
    return static_cast<int>(AnalysisStage::Scoring) + 1;
}

} // namespace

MainWindow::MainWindow(AnalysisController& controller, QWidget* parent)
    : QMainWindow(parent)
    , controller_(controller)
    , pages_(new QStackedWidget(this))
    , dashboard_(new DashboardView(pages_))
    , workspace_(new QTabWidget(pages_)) {
    setWindowTitle(QStringLiteral("Sectoryn"));
    resize(kDefaultWidth, kDefaultHeight);
    setAcceptDrops(true);

    workspace_->setDocumentMode(true);
    pages_->addWidget(dashboard_);
    pages_->addWidget(workspace_);
    setCentralWidget(pages_);

    createMenus();
    createStatusBar();

    connect(dashboard_, &DashboardView::openRequested, this, &MainWindow::openFileDialog);
    connect(dashboard_, &DashboardView::filesDropped, this,
            [this](const QStringList& files) { analyzeFile(files.front()); });
    connect(dashboard_, &DashboardView::resultActivated, this, &MainWindow::showResult);

    connect(&controller_, &AnalysisController::started, this, [this](const QString& path) {
        setBusy(true, tr("Analyzing %1").arg(QFileInfo(path).fileName()));
    });
    connect(&controller_, &AnalysisController::progressed, this, [this](AnalysisStage stage) {
        progress_->setValue(static_cast<int>(stage) + 1);
        status_->setText(toQString(toString(stage)));
    });
    connect(&controller_, &AnalysisController::finished, this,
            [this](const SharedResult& result) {
                setBusy(false, tr("Analysis complete"));
                dashboard_->addResult(result);
                showResult(result);
            });
    connect(&controller_, &AnalysisController::failed, this,
            [this](const QString& path, const QString& message) {
                setBusy(false, tr("Analysis failed"));
                QMessageBox::warning(this, tr("Analysis failed"),
                                     tr("%1 could not be analyzed.\n\n%2")
                                         .arg(QFileInfo(path).fileName(), message));
            });
    connect(&controller_, &AnalysisController::cancelled, this,
            [this] { setBusy(false, tr("Analysis cancelled")); });
}

void MainWindow::addPanel(AnalysisPanel* panel) {
    panels_.push_back(panel);
    workspace_->addTab(panel, panel->title());
    connect(panel, &AnalysisPanel::evidenceActivated, this, &MainWindow::revealEvidence);
    if (current_) {
        panel->showResult(current_);
    } else {
        panel->clear();
    }
}

void MainWindow::openFileDialog() {
    const QString path = QFileDialog::getOpenFileName(
        this, tr("Open File for Analysis"), lastDirectory_,
        tr("Executables (*.exe *.dll *.sys *.ocx *.scr *.cpl *.efi);;All files (*)"));
    if (!path.isEmpty()) {
        lastDirectory_ = QFileInfo(path).absolutePath();
        analyzeFile(path);
    }
}

void MainWindow::analyzeFile(const QString& path) {
    if (controller_.isBusy()) {
        statusBar()->showMessage(tr("Another analysis is still running"), 4000);
        return;
    }
    controller_.analyze(path);
}

void MainWindow::showResult(const SharedResult& result) {
    if (!result) {
        return;
    }
    current_ = result;
    for (AnalysisPanel* panel : panels_) {
        panel->showResult(result);
    }
    const QString name =
        QFileInfo(QString::fromStdU16String(result->file.path.u16string())).fileName();
    setWindowTitle(QStringLiteral("%1 - Sectoryn").arg(name));
    pages_->setCurrentWidget(workspace_);
    workspace_->setCurrentIndex(0);
    Q_EMIT resultShown(result);
}

void MainWindow::showDashboard() {
    pages_->setCurrentWidget(dashboard_);
}

void MainWindow::closeEvent(QCloseEvent* event) {
    // The controller's destructor joins the worker; cancelling first keeps that wait short.
    controller_.cancel();
    QMainWindow::closeEvent(event);
}

void MainWindow::dragEnterEvent(QDragEnterEvent* event) {
    if (!localFiles(event->mimeData()).isEmpty()) {
        event->acceptProposedAction();
    }
}

void MainWindow::dropEvent(QDropEvent* event) {
    const QStringList files = localFiles(event->mimeData());
    if (!files.isEmpty()) {
        event->acceptProposedAction();
        analyzeFile(files.front());
    }
}

void MainWindow::createMenus() {
    QMenu* fileMenu = menuBar()->addMenu(tr("&File"));
    QAction* open = fileMenu->addAction(tr("&Open File..."), this, &MainWindow::openFileDialog);
    open->setShortcut(QKeySequence::Open);
    fileMenu->addSeparator();
    QAction* quit = fileMenu->addAction(tr("&Quit"), this, &QWidget::close);
    quit->setShortcut(QKeySequence::Quit);

    QMenu* viewMenu = menuBar()->addMenu(tr("&View"));
    QAction* dashboard = viewMenu->addAction(tr("&Dashboard"), this, &MainWindow::showDashboard);
    dashboard->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_D));
    QAction* workspace = viewMenu->addAction(tr("&Analysis Workspace"), this, [this] {
        if (current_) {
            pages_->setCurrentWidget(workspace_);
        }
    });
    workspace->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_W));

    toolsMenu_ = menuBar()->addMenu(tr("&Tools"));

    QMenu* helpMenu = menuBar()->addMenu(tr("&Help"));
    helpMenu->addAction(tr("&About Sectoryn"), this, [this] {
        QMessageBox::about(
            this, tr("About Sectoryn"),
            tr("Sectoryn %1\nStatic PE analysis and malware triage workbench.\n\n"
               "Files are inspected statically and are never executed. Triage outcomes rank "
               "files for attention; they do not prove that a file is malicious or safe.")
                .arg(QApplication::applicationVersion()));
    });
}

void MainWindow::createStatusBar() {
    status_ = new QLabel(tr("Ready"), this);
    status_->setTextFormat(Qt::PlainText);
    progress_ = new QProgressBar(this);
    progress_->setRange(0, stageCount());
    progress_->setTextVisible(false);
    progress_->setFixedWidth(160);
    progress_->hide();
    cancel_ = new QPushButton(tr("Cancel"), this);
    cancel_->hide();
    connect(cancel_, &QPushButton::clicked, &controller_, &AnalysisController::cancel);

    statusBar()->addWidget(status_, 1);
    statusBar()->addPermanentWidget(progress_);
    statusBar()->addPermanentWidget(cancel_);
}

void MainWindow::setBusy(bool busy, const QString& message) {
    status_->setText(message);
    progress_->setValue(0);
    progress_->setVisible(busy);
    cancel_->setVisible(busy);
}

void MainWindow::revealEvidence(const Evidence& evidence) {
    for (AnalysisPanel* panel : panels_) {
        if (panel != sender() && panel->reveal(evidence)) {
            workspace_->setCurrentWidget(panel);
            return;
        }
    }
    statusBar()->showMessage(tr("No view shows this evidence in more detail"), 4000);
}

} // namespace sectoryn::ui
