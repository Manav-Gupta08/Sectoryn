# Detection methodology

Sectoryn reports observations, not verdicts. Every finding names the rule that produced it,
the evidence it saw, why that can matter, benign explanations, and what to check next.

## Findings

| Field | Meaning |
|---|---|
| Rule ID | Stable identifier, e.g. `section.writable_executable`. Never reused with another meaning. |
| Severity | How much the observation matters *if it is what it looks like*: informational, low, medium, high, critical. |
| Confidence | How strongly the evidence supports the finding itself: low, medium, high. |
| Evidence | Up to 25 items, each with a description, structure and, where known, a file offset. |
| Explanation / limitations / next step | Why it matters, common benign causes, and how to confirm. |
| ATT&CK | Technique IDs where a mapping is reasonable. |
| Correlation group | Findings that describe the same behavior share a group and are scored once. |

Severity and confidence are kept apart: a corrupt header is certain (high confidence) but not
alarming (low severity); a suspicious API combination may matter a lot (high severity) while
being weakly supported (medium confidence).

## Built-in rules

| Rule family | Finding IDs | Looks at |
|---|---|---|
| `header.structure` | `header.entry_point_unusual`, `header.inconsistent` | Structural issues found by the PE validator |
| `section.permissions` | `section.writable_executable`, `section.executable_without_code_flag`, `section.shared_writable` | Section characteristics |
| `section.layout` | `section.overlap`, `section.data_outside_file`, `section.layout_inconsistent`, `section.unusual_name`, `section.packer_name` | Section ranges and names |
| `entropy` | `entropy.high_section`, `entropy.packed_code`, `entropy.high_overlay` | Section and overlay entropy (see [entropy.md](entropy.md)) |
| `api` | `api.process_injection`, `api.runtime_code_modification`, `api.download_and_execute`, `api.service_installation`, `api.file_encryption`, `api.input_capture`, `api.debugger_detection`, `api.privilege_adjustment` | Combinations of imported functions from `resources/rules/api_indicators.json` |
| `strings` | `strings.network`, `strings.paths`, `strings.persistence`, `strings.command_line`, `strings.powershell`, `strings.encoded_data` | Classified indicators from extracted strings |
| `signature.layout` | `signature.data_after_certificate`, `signature.certificate_inside_image` | Position of the certificate table |

Optional modules add:

| Module | Finding IDs |
|---|---|
| Authenticode (Windows) | `signature.invalid`, `signature.untrusted` |
| YARA | `yara.<rule name>`, one per matching rule, all in the `yara` group |

API rules require a *combination* of functions (for example opening a process, writing its
memory and starting a thread in it). A single imported function is never a finding on its own.

A missing or valid signature is not a finding. Neither says anything about intent.

## Risk score

The score orders files for attention. It is not a probability of maliciousness.

1. Each finding gets `points = severityPoints[severity] × confidenceFactor[confidence]` with
   severity points 0 / 5 / 15 / 30 / 50 (informational … critical) and confidence factors
   0.5 / 0.75 / 1.0 (low … high).
2. Within each correlation group only the finding with the most points counts. The others are
   listed as "correlated with" it.
3. The sum is capped at 100.

| Outcome | Condition |
|---|---|
| High priority | score ≥ 50 |
| Suspicious indicators | score ≥ 20 |
| Analysis incomplete | score < 20 and some part of the analysis did not complete |
| No significant indicators | score < 20 and the analysis completed |
| Unsupported or invalid | not a PE file, or the PE headers could not be parsed |

"No significant indicators" means the rules found nothing that reached the threshold. It does
not mean the file is safe. Every contribution is shown in the Findings panel and in reports so
the arithmetic can be checked.

## What is not inspected

* Behavior at run time, unpacked or decrypted content, and code reached only dynamically.
* .NET metadata and managed code beyond the PE container.
* Catalog signatures (Windows system files are often signed that way, not embedded).
* Revocation information that Windows has not already cached.
