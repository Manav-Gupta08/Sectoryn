#pragma once

#include "core/Config.hpp"

#include <QDialog>

class QComboBox;
class QLabel;
class QLineEdit;
class QSpinBox;

namespace sectoryn::ui {

// Edits a copy of the configuration. config() holds the edited values once the dialog has been
// accepted; accepting is refused while the values are invalid.
class SettingsDialog final : public QDialog {
    Q_OBJECT

public:
    explicit SettingsDialog(Config config, QWidget* parent = nullptr);

    [[nodiscard]] const Config& config() const noexcept { return config_; }

public Q_SLOTS:
    void accept() override;

private:
    void load();
    [[nodiscard]] Config collect() const;

    Config config_;
    // Sizes are edited in MiB. The loaded values are kept so that a byte count which is not a
    // whole number of MiB survives unless the user changes it.
    int loadedFileMiB_ = 0;
    int loadedStringMiB_ = 0;

    QComboBox* logLevel_;
    QSpinBox* workers_;
    QSpinBox* queuedJobs_;
    QSpinBox* maxFileMiB_;
    QSpinBox* maxSections_;
    QSpinBox* maxModules_;
    QSpinBox* maxFunctions_;
    QSpinBox* maxExports_;
    QSpinBox* maxResources_;
    QSpinBox* maxStrings_;
    QSpinBox* maxStringMiB_;
    QSpinBox* minStringLength_;
    QSpinBox* maxStringLength_;
    QLineEdit* yaraFolder_;
    QLabel* error_;
};

} // namespace sectoryn::ui
