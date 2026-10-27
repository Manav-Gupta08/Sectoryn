#pragma once

#include "core/Config.hpp"
#include "core/Logger.hpp"
#include "engine/AnalysisEngine.hpp"
#include "engine/AnalysisResult.hpp"
#include "storage/HistoryStore.hpp"

#include <QApplication>
#include <QString>

#include <memory>
#include <optional>

namespace sectoryn {

namespace ui {
class AnalysisController;
class JobManagerView;
class MainWindow;
class YaraView;
} // namespace ui

// Composition root: loads configuration, builds the engine and wires the user interface. This
// is the only place that knows about every module.
class Application {
public:
    Application(int& argc, char** argv);
    ~Application();

    Application(const Application&) = delete;
    Application& operator=(const Application&) = delete;
    Application(Application&&) = delete;
    Application& operator=(Application&&) = delete;

    [[nodiscard]] int run();

private:
    // Builds the engine with the optional modules the configuration enables. yaraStatus_ is
    // updated to describe the YARA rules that were loaded, or why none were.
    [[nodiscard]] Result<AnalysisEngine> createEngine(const Config& config);
    void openLogFile();
    void openHistory();
    void editSettings();
    void recordHistory(const AnalysisResult& result);
    void showHistoryFor(const AnalysisResult& result);

    // Destruction runs bottom-up: the batch window and main window go first, then the controller
    // (which waits for a running analysis), and QApplication last.
    Logger logger_;
    Config config_;
    // Empty when there is no writable data directory.
    std::optional<HistoryStore> history_;
    QApplication qtApp_;
    std::unique_ptr<ui::AnalysisController> controller_;
    std::unique_ptr<ui::MainWindow> window_;
    std::unique_ptr<ui::JobManagerView> jobs_;
    // Owned by window_.
    ui::YaraView* yaraView_ = nullptr;
    QString yaraStatus_;
};

} // namespace sectoryn
