#include "detectors/yara/YaraRuntime.hpp"

#include "detectors/yara/YaraApi.hpp"

#include <format>
#include <mutex>

namespace sectoryn {

namespace {

std::mutex& runtimeMutex() {
    static std::mutex mutex;
    return mutex;
}

std::weak_ptr<YaraRuntime>& currentRuntime() {
    static std::weak_ptr<YaraRuntime> runtime;
    return runtime;
}

} // namespace

std::string_view yaraLibraryVersion() noexcept {
    return YR_VERSION;
}

Result<std::shared_ptr<YaraRuntime>> YaraRuntime::acquire() {
    const std::lock_guard lock(runtimeMutex());
    if (std::shared_ptr<YaraRuntime> existing = currentRuntime().lock()) {
        return existing;
    }
    if (const int status = yr_initialize(); status != ERROR_SUCCESS) {
        return Error{ErrorCode::Internal,
                     std::format("libyara could not be initialized (error {})", status)};
    }
    std::shared_ptr<YaraRuntime> runtime(new YaraRuntime());
    currentRuntime() = runtime;
    return runtime;
}

YaraRuntime::~YaraRuntime() {
    const std::lock_guard lock(runtimeMutex());
    yr_finalize();
}

} // namespace sectoryn
