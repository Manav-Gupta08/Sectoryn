#include "detectors/Finding.hpp"

namespace sectoryn {

std::string_view toString(Severity severity) noexcept {
    switch (severity) {
    case Severity::Informational:
        return "informational";
    case Severity::Low:
        return "low";
    case Severity::Medium:
        return "medium";
    case Severity::High:
        return "high";
    case Severity::Critical:
        return "critical";
    }
    return "unknown";
}

std::string_view toString(Confidence confidence) noexcept {
    switch (confidence) {
    case Confidence::Low:
        return "low";
    case Confidence::Medium:
        return "medium";
    case Confidence::High:
        return "high";
    }
    return "unknown";
}

} // namespace sectoryn
