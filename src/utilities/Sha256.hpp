#pragma once

#include "core/CancellationToken.hpp"
#include "core/Result.hpp"

#include <array>
#include <cstddef>
#include <memory>
#include <span>
#include <string>

struct evp_md_ctx_st;

namespace sectoryn {

class FileReader;

// Incremental SHA-256 backed by OpenSSL EVP.
class Sha256 {
public:
    static constexpr std::size_t kDigestBytes = 32;
    using Digest = std::array<std::byte, kDigestBytes>;

    [[nodiscard]] static Result<Sha256> create();

    [[nodiscard]] Status update(std::span<const std::byte> data);

    // Finalizes the hash. The object cannot be updated or finished again afterwards.
    [[nodiscard]] Result<Digest> finish();

    [[nodiscard]] static Result<Digest> hash(std::span<const std::byte> data);
    [[nodiscard]] static std::string toHex(const Digest& digest);

private:
    struct ContextDeleter {
        void operator()(evp_md_ctx_st* context) const noexcept;
    };

    explicit Sha256(std::unique_ptr<evp_md_ctx_st, ContextDeleter> context);

    std::unique_ptr<evp_md_ctx_st, ContextDeleter> context_;
};

// Hashes the whole file in bounded chunks; memory use does not depend on the file size.
[[nodiscard]] Result<Sha256::Digest> sha256File(FileReader& reader, std::size_t chunkBytes,
                                                const CancellationToken& token);

} // namespace sectoryn
