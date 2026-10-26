#include "utilities/FileIo.hpp"

#include <format>
#include <fstream>
#include <random>
#include <system_error>

namespace sectoryn {

namespace {

std::filesystem::path temporarySibling(const std::filesystem::path& path) {
    std::random_device random;
    std::filesystem::path temporary = path;
    temporary += std::format(".{:08x}.tmp", random());
    return temporary;
}

} // namespace

Result<std::string> readSmallFile(const std::filesystem::path& path, std::size_t maxBytes) {
    std::error_code error;
    if (!std::filesystem::is_regular_file(path, error)) {
        return Error{ErrorCode::IoFailure, "not a regular file"};
    }
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return Error{ErrorCode::IoFailure, "cannot open the file"};
    }
    // One byte past the limit shows whether the file is too large.
    std::string text(maxBytes + 1, '\0');
    in.read(text.data(), static_cast<std::streamsize>(text.size()));
    if (in.bad()) {
        return Error{ErrorCode::IoFailure, "cannot read the file"};
    }
    const auto bytesRead = static_cast<std::size_t>(in.gcount());
    if (bytesRead > maxBytes) {
        return Error{ErrorCode::ResourceLimitExceeded,
                     std::format("the file is larger than {} bytes", maxBytes)};
    }
    text.resize(bytesRead);
    return text;
}

Status writeFileAtomically(const std::filesystem::path& path, std::string_view contents) {
    const std::filesystem::path temporary = temporarySibling(path);
    {
        std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            return Error{ErrorCode::IoFailure, "cannot create a file in the target directory"};
        }
        out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
        out.close();
        if (!out) {
            std::error_code ignored;
            std::filesystem::remove(temporary, ignored);
            return Error{ErrorCode::IoFailure, "cannot write the file"};
        }
    }

    std::error_code error;
    std::filesystem::rename(temporary, path, error);
    std::error_code existsError;
    if (error && std::filesystem::exists(path, existsError)) {
        // Some platforms refuse to rename over an existing file. The old file is then removed
        // first, which leaves a short window in which neither version exists.
        std::error_code removeError;
        std::filesystem::remove(path, removeError);
        error.clear();
        std::filesystem::rename(temporary, path, error);
    }
    if (error) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        return Error{ErrorCode::IoFailure,
                     std::format("cannot replace the file: {}", error.message())};
    }
    return {};
}

} // namespace sectoryn
