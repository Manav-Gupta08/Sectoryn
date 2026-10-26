#include "platform/win/AuthenticodeVerifier.hpp"

// clang-format off
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
// clang-format on

#include <cstdint>
#include <format>
#include <memory>
#include <string>
#include <vector>

namespace sectoryn {

namespace {

// HRESULTs from WinTrust.h and WinError.h, spelled out to avoid the C casts in the SDK macros.
constexpr LONG hresult(std::uint32_t value) noexcept {
    return static_cast<LONG>(value);
}

constexpr LONG kNoSignature = hresult(0x800B0100);
constexpr LONG kSubjectFormUnknown = hresult(0x800B0003);
constexpr LONG kProviderUnknown = hresult(0x800B0001);
constexpr LONG kBadDigest = hresult(0x80096010);
constexpr LONG kCertSignature = hresult(0x80096004);
constexpr LONG kExplicitDistrust = hresult(0x800B0111);
constexpr LONG kSubjectNotTrusted = hresult(0x800B0004);
constexpr LONG kUntrustedRoot = hresult(0x800B0109);
constexpr LONG kUntrustedTestRoot = hresult(0x800B010D);
constexpr LONG kExpired = hresult(0x800B0101);
constexpr LONG kRevoked = hresult(0x800B010C);
constexpr LONG kChaining = hresult(0x800B010A);
constexpr LONG kSecuritySettings = hresult(0x80092026);

struct StoreCloser {
    void operator()(void* store) const noexcept { CertCloseStore(store, 0); }
};
struct MessageCloser {
    void operator()(void* message) const noexcept { CryptMsgClose(message); }
};
struct CertificateFreer {
    void operator()(const CERT_CONTEXT* certificate) const noexcept {
        CertFreeCertificateContext(certificate);
    }
};

std::string toUtf8(const wchar_t* text, int length) {
    if (length <= 0) {
        return {};
    }
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, text, length, nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) {
        return {};
    }
    std::string result(static_cast<std::size_t>(bytes), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, length, result.data(), bytes, nullptr, nullptr);
    return result;
}

std::string certificateName(const CERT_CONTEXT* certificate, DWORD flags) {
    const DWORD length =
        CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nullptr, nullptr, 0);
    if (length <= 1) {
        return {};
    }
    std::wstring name(length, L'\0');
    CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nullptr, name.data(),
                       length);
    return toUtf8(name.c_str(), static_cast<int>(length - 1));
}

// Serial numbers are stored least significant byte first.
std::string serialNumber(const CRYPT_INTEGER_BLOB& blob) {
    std::string text;
    for (DWORD i = blob.cbData; i > 0; --i) {
        text += std::format("{:02x}", blob.pbData[i - 1]);
    }
    return text;
}

// Reads the signer of the embedded PKCS #7 signature. Leaves the fields empty when the file has
// none or it cannot be decoded; WinVerifyTrust has already reported why.
void readSigner(const std::wstring& file, SignatureVerification& result) {
    DWORD encoding = 0;
    DWORD contentType = 0;
    DWORD formatType = 0;
    HCERTSTORE rawStore = nullptr;
    HCRYPTMSG rawMessage = nullptr;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, file.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
                          0, &encoding, &contentType, &formatType, &rawStore, &rawMessage,
                          nullptr)) {
        return;
    }
    const std::unique_ptr<void, StoreCloser> store(rawStore);
    const std::unique_ptr<void, MessageCloser> message(rawMessage);

    DWORD size = 0;
    if (!CryptMsgGetParam(message.get(), CMSG_SIGNER_INFO_PARAM, 0, nullptr, &size) || size == 0) {
        return;
    }
    std::vector<std::uint64_t> buffer((size + sizeof(std::uint64_t) - 1) / sizeof(std::uint64_t));
    if (!CryptMsgGetParam(message.get(), CMSG_SIGNER_INFO_PARAM, 0, buffer.data(), &size)) {
        return;
    }
    const auto* signer = reinterpret_cast<const CMSG_SIGNER_INFO*>(buffer.data());

    CERT_INFO wanted{};
    wanted.Issuer = signer->Issuer;
    wanted.SerialNumber = signer->SerialNumber;
    const std::unique_ptr<const CERT_CONTEXT, CertificateFreer> certificate(
        CertFindCertificateInStore(store.get(), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                                   CERT_FIND_SUBJECT_CERT, &wanted, nullptr));
    if (!certificate) {
        return;
    }
    result.signer = certificateName(certificate.get(), 0);
    result.issuer = certificateName(certificate.get(), CERT_NAME_ISSUER_FLAG);
    result.serialNumber = serialNumber(certificate->pCertInfo->SerialNumber);
}

SignatureVerification classify(LONG status) {
    SignatureVerification result;
    if (status == ERROR_SUCCESS) {
        result.state = SignatureState::Verified;
        result.detail = "the signature is valid and chains to a trusted root";
    } else if (status == kNoSignature || status == kSubjectFormUnknown ||
               status == kProviderUnknown) {
        result.state = SignatureState::Unsigned;
        result.detail = "the file has no embedded Authenticode signature (it may still be "
                        "signed through a Windows catalog, which is not checked)";
    } else if (status == kBadDigest || status == kCertSignature) {
        result.state = SignatureState::Invalid;
        result.detail = "the file does not match its signature or the signature is corrupt";
    } else if (status == kExplicitDistrust || status == kSubjectNotTrusted ||
               status == kUntrustedRoot || status == kUntrustedTestRoot || status == kExpired ||
               status == kRevoked || status == kChaining || status == kSecuritySettings) {
        result.state = SignatureState::Untrusted;
        result.detail = std::format("the signature is intact but not trusted (WinVerifyTrust "
                                    "status {:#010x})",
                                    static_cast<std::uint32_t>(status));
    } else {
        result.state = SignatureState::Unavailable;
        result.detail = std::format("WinVerifyTrust could not complete (status {:#010x})",
                                    static_cast<std::uint32_t>(status));
    }
    return result;
}

} // namespace

SignatureVerification AuthenticodeVerifier::verify(const std::filesystem::path& path,
                                                   const CancellationToken& token) const {
    if (token.stop_requested()) {
        return {SignatureState::Unavailable, "verification was cancelled", {}, {}, {}, true};
    }

    const std::wstring file = path.wstring();
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = file.c_str();

    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(nullptr, &action, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &data);

    SignatureVerification result = classify(status);
    if (result.state != SignatureState::Unsigned) {
        readSigner(file, result);
    }
    return result;
}

std::unique_ptr<ISignatureVerifier> createPlatformSignatureVerifier() {
    return std::make_unique<AuthenticodeVerifier>();
}

} // namespace sectoryn
