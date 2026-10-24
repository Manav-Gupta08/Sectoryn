#include "utilities/Sha256.hpp"

#include "utilities/FileReader.hpp"

#include <openssl/evp.h>

#include <utility>

namespace sectoryn {

void Sha256::ContextDeleter::operator()(evp_md_ctx_st* context) const noexcept {
    EVP_MD_CTX_free(context);
}

Sha256::Sha256(std::unique_ptr<evp_md_ctx_st, ContextDeleter> context)
    : context_(std::move(context)) {}

Result<Sha256> Sha256::create() {
    std::unique_ptr<evp_md_ctx_st, ContextDeleter> context(EVP_MD_CTX_new());
    if (!context) {
        return Error{ErrorCode::Internal, "cannot allocate digest context"};
    }
    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        return Error{ErrorCode::Internal, "cannot initialize SHA-256"};
    }
    return Sha256(std::move(context));
}

Status Sha256::update(std::span<const std::byte> data) {
    if (!context_) {
        return Error{ErrorCode::Internal, "SHA-256 context already finished"};
    }
    if (EVP_DigestUpdate(context_.get(), data.data(), data.size()) != 1) {
        return Error{ErrorCode::Internal, "SHA-256 update failed"};
    }
    return {};
}

Result<Sha256::Digest> Sha256::finish() {
    if (!context_) {
        return Error{ErrorCode::Internal, "SHA-256 context already finished"};
    }

    Digest digest{};
    unsigned int length = 0;
    const int finished = EVP_DigestFinal_ex(
        context_.get(), reinterpret_cast<unsigned char*>(digest.data()), &length);
    context_.reset();
    if (finished != 1 || length != kDigestBytes) {
        return Error{ErrorCode::Internal, "SHA-256 finalization failed"};
    }
    return digest;
}

Result<Sha256::Digest> Sha256::hash(std::span<const std::byte> data) {
    Result<Sha256> hasher = create();
    if (!hasher) {
        return std::move(hasher).error();
    }
    if (Status status = hasher.value().update(data); !status) {
        return std::move(status).error();
    }
    return hasher.value().finish();
}

std::string Sha256::toHex(const Digest& digest) {
    constexpr char kHexDigits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(digest.size() * 2);
    for (const std::byte b : digest) {
        const auto value = std::to_integer<unsigned>(b);
        hex.push_back(kHexDigits[value >> 4U]);
        hex.push_back(kHexDigits[value & 0x0FU]);
    }
    return hex;
}

Result<Sha256::Digest> sha256File(FileReader& reader, std::size_t chunkBytes,
                                  const CancellationToken& token) {
    Result<Sha256> hasher = Sha256::create();
    if (!hasher) {
        return std::move(hasher).error();
    }

    Status streamed = reader.forEachChunk(
        {0, reader.size()}, chunkBytes, token,
        [&hasher](std::span<const std::byte> chunk) { return hasher.value().update(chunk); });
    if (!streamed) {
        return std::move(streamed).error();
    }
    return hasher.value().finish();
}

} // namespace sectoryn
