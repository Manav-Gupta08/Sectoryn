# Supported platforms

| Platform | Toolchain | Status |
|---|---|---|
| Ubuntu 24.04 (x86-64) | GCC 13, Qt 6.4, OpenSSL 3.0 | Developed and tested here; covered by the CI workflow |
| Windows 10/11 (x86-64) | MSYS2 UCRT64: GCC, Qt 6, OpenSSL 3 | Covered by the CI workflow |
| Other Linux distributions | GCC 13+ or Clang 16+, Qt 6.4+ | Expected to work; not tested |
| macOS | – | Not supported. The code is portable C++ and Qt, but nothing is built or tested there |

## Differences between platforms

| Feature | Windows | Linux |
|---|---|---|
| PE parsing, hashing, entropy, strings, rules, reports, batches | Yes | Yes |
| YARA scanning | When built against libyara 4.3+ | When built against libyara 4.3+ |
| Authenticode verification | WinVerifyTrust, cached revocation data only | Not available; the certificate table's position is still checked |
| Reputation lookup | Yes (opt-in) | Yes (opt-in) |
| AddressSanitizer / UBSan builds | No (MinGW ships no sanitizer runtimes) | `linux-sanitize` preset |
| libFuzzer harnesses | – | With Clang (`SECTORYN_BUILD_FUZZERS=ON`) |

On Linux, the Signature panel says that verification is unavailable instead of showing a
result, and no coverage gap is recorded for it.
