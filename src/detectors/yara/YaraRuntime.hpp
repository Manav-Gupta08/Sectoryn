#pragma once

#include "core/Result.hpp"

#include <memory>
#include <string_view>

namespace sectoryn {

// Version of the libyara that Sectoryn was built with, e.g. "4.5.8".
[[nodiscard]] std::string_view yaraLibraryVersion() noexcept;

// libyara keeps process-wide state that must be initialized before any compiler or rule set is
// created and finalized after the last one is gone. Every object that uses libyara holds one of
// these; the state lives as long as any of them does.
class YaraRuntime {
public:
    [[nodiscard]] static Result<std::shared_ptr<YaraRuntime>> acquire();

    ~YaraRuntime();

    YaraRuntime(const YaraRuntime&) = delete;
    YaraRuntime& operator=(const YaraRuntime&) = delete;
    YaraRuntime(YaraRuntime&&) = delete;
    YaraRuntime& operator=(YaraRuntime&&) = delete;

private:
    YaraRuntime() = default;
};

} // namespace sectoryn
