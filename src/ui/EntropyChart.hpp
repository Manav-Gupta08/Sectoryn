#pragma once

#include "analysis/EntropyProfile.hpp"

#include <QString>
#include <QWidget>

#include <cstdint>
#include <optional>
#include <vector>

namespace sectoryn::ui {

struct ChartBar {
    QString label;
    std::optional<double> value;
    QString tooltip;
};

// Plots entropy on a fixed 0-8 bits-per-byte scale, either as one bar per range or as a line
// across the file. Exact values are shown in tooltips; EntropyPanel also lists them in a table.
class EntropyChart final : public QWidget {
    Q_OBJECT

public:
    explicit EntropyChart(QWidget* parent = nullptr);

    void setBars(std::vector<ChartBar> bars);
    void setProfile(std::vector<EntropyPoint> points, std::uint64_t fileSize);
    void clear();

    // Reference line drawn across the chart, e.g. the high-entropy threshold used by the rules.
    void setThreshold(double threshold) { threshold_ = threshold; }

    [[nodiscard]] QSize sizeHint() const override;
    [[nodiscard]] QSize minimumSizeHint() const override;

protected:
    void paintEvent(QPaintEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;

private:
    [[nodiscard]] QRectF plotArea() const;
    [[nodiscard]] double yFor(double entropy, const QRectF& plot) const;
    [[nodiscard]] int itemAt(double x) const;

    enum class Mode { Empty, Bars, Profile };

    Mode mode_ = Mode::Empty;
    std::vector<ChartBar> bars_;
    std::vector<EntropyPoint> points_;
    std::uint64_t fileSize_ = 0;
    // Not drawn while zero.
    double threshold_ = 0.0;
};

} // namespace sectoryn::ui
