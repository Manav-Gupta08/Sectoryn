# Threat model

Sectoryn exists to open files that may have been crafted to attack the tools that open them.
This page lists what is trusted, what is not, and how each untrusted input is contained.

## Assets

* The analyst's machine and account: Sectoryn must not run, load or install anything taken from
  an analyzed file.
* The integrity of results: a file must not be able to hide findings, forge findings or make an
  incomplete analysis look complete.
* The analyst's privacy: nothing about an analyzed file leaves the machine without explicit
  consent.

## Trust boundaries

| Input | Trust | Handling |
|---|---|---|
| Analyzed file bytes and every PE field | Hostile | Read only through `FileReader`; every offset, size and count is range-checked with `CheckedMath` before use |
| Strings, import/export names, resource names, PDB paths | Hostile | Shown as plain text in the UI (`Qt::PlainText`), HTML-escaped in reports, serialized by nlohmann/json |
| Certificate fields | Untrusted unless Windows verified the signature | Labelled as such |
| PE timestamps | Untrusted metadata | Never used as a compile time |
| YARA rule files | Semi-trusted (chosen by the user) | Size and count limits, `include` refused, scanning time-limited |
| Configuration file | Local user | Size-limited, unknown keys rejected, every value range-checked |
| Reputation responses | External | Size-limited, parsed defensively, shown apart from local results and never scored |
| Analysis history | Local user | Bounded, rewritten atomically, a damaged file is replaced |

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Code execution through the analyzed file | The file is never executed, loaded as a library, or passed to a shell. WinVerifyTrust reads it as data. |
| Memory corruption in parsing | Project-owned validation of all ranges; LIEF output is re-checked; malformed and fuzz-derived inputs in the test suite; ASan/UBSan CI job; fuzz harnesses |
| Integer overflow in offset arithmetic | `checkedAdd`/`rangeFits` for every derived offset; regression tests for values near 2<sup>32</sup> |
| Resource exhaustion (huge files, millions of strings, deep resources, many sections) | Limits in `AnalysisLimits` enforced by the engine; stages that hit a limit say so and the outcome becomes "analysis incomplete" |
| Script injection through reports | All file-derived text is escaped; reports carry a Content-Security-Policy that forbids scripts and remote content |
| Markup injection in the UI | All labels and views showing file data use plain text |
| Hiding findings via parser disagreement | Parse errors and unreadable structures are reported as coverage gaps, never as "absent" |
| Silent network disclosure | Reputation lookups are off by default, need an API key and an explicit checkbox per session, and state what will be sent; the file itself is never uploaded |
| Malicious YARA rules | `include` is refused, sources and sizes are capped, scans have a timeout |

## Out of scope

* Dynamic behavior. Sectoryn does not run samples, so anything decided at run time is invisible.
* Vulnerabilities in the operating system's own handling of the file (for example Explorer
  previewing it before Sectoryn opens it).
* An attacker with write access to the analyst's account or Sectoryn's installation.
