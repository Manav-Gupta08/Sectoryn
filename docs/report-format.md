# Report formats

Sectoryn writes two kinds of report for an analyzed file: a JSON document for tools and an HTML
document for people. Both are generated from the same analysis result
(`src/reports/JsonReport.cpp`, `src/reports/HtmlReport.cpp`) and contain the same facts.

## Options

| Option | Default | Effect |
|---|---|---|
| Include strings | off | Adds every extracted string. Strings can run to many megabytes. Indicators found in strings are always included. |
| Include full path | off | Writes the full path of the analyzed file instead of only its name. Paths can reveal user and folder names. |
| Include run times | on | Adds when the analysis started and finished. |

Without run times, two reports of the same file made by the same Sectoryn version are identical
byte for byte, so reports can be compared with ordinary diff tools.

## JSON report

The document is UTF-8, indented by two spaces, and ends with a newline. Keys always appear in
the order listed here. Text that is not valid UTF-8 is written as U+FFFD.

### Versioning

`schema` is always `"sectoryn-report"`. `schema_version` is currently `1`. It is raised when a
field is removed or changes meaning; adding a field does not raise it, so consumers should
ignore keys they do not know.

### Conventions

- Numbers from the file (offsets, sizes, RVAs, flags) are JSON integers, never hex strings.
- Fields that do not apply are `null` rather than missing, e.g. `pe` for a file that is not a PE,
  or `entropy` for a section without raw data.
- Enumerations use fixed lowercase tokens such as `"high_priority"` or `"parser_error"`. Fields
  ending in `_label` or `_name` hold display text that may change between versions.
- Times are ISO 8601 in UTC with millisecond precision, e.g. `"2026-10-27T14:03:12.415Z"`.
- A structure that may be missing, damaged or unread has a `status` object:

  ```json
  { "state": "present", "detail": "" }
  ```

  `state` is one of `not_inspected`, `present`, `absent`, `invalid`, `unsupported`,
  `parser_error` or `incomplete`. Only `present` and `incomplete` structures carry data; for the
  others, an empty list means "unknown", not "none".

### Top level

| Key | Content |
|---|---|
| `schema`, `schema_version` | See above. |
| `generator` | `name`, `version`, and the PE `parser` with its `parser_version`. |
| `run` | `started`, `finished`, `duration_ms`. Present only with run times enabled. |
| `file` | `name` (or full path), `size`, `sha256`, `modified` (may be `null`). |
| `identification` | `kind` (`pe`, `mz_without_pe`, `elf`, `zip`, ...), `detail`, `pe_header_offset`. |
| `assessment` | Triage outcome; see below. |
| `findings` | List of findings; see below. |
| `rules` | `skipped` and `failed` lists of `{rule_id, reason}`. |
| `warnings` | Problems that did not stop the analysis. |
| `pe` | Parsed PE structures, or `null`. |
| `entropy` | Whole-file statistics and the entropy profile, or `null`. |
| `strings` | `count`, `limit_reached`, and `items` when strings are included; `null` if strings were not extracted. |
| `indicators` | `{kind, value, string_index, offset}` for URLs, paths, registry keys and similar text. |
| `enrichments` | Results of optional checks such as signature verification or YARA scanning. |

### Assessment

| Key | Content |
|---|---|
| `outcome` | `no_significant_indicators`, `suspicious_indicators`, `high_priority`, `analysis_incomplete` or `unsupported_or_invalid`. |
| `outcome_label` | The same outcome as display text. |
| `score`, `max_score` | Score from 0 to 100. It ranks files for attention and is not a probability. |
| `explanation` | How the outcome was reached. |
| `coverage_gaps` | Parts of the analysis that did not complete. |
| `contributions` | Per finding: `finding_index`, `rule_id`, `points`, `counted`, and `correlated_with` for findings scored as part of another finding's group. |

The outcome describes how much attention a file deserves. None of the outcomes states that a file
is malicious or that it is safe.

### Findings

| Key | Content |
|---|---|
| `rule_id` | Stable identifier, e.g. `section.writable_executable`. |
| `title`, `description` | What was found. |
| `severity` | `informational`, `low`, `medium`, `high` or `critical`. |
| `confidence` | `low`, `medium` or `high`. |
| `evidence` | Up to 25 `{description, location, file_offset}` items; `file_offset` may be `null`. |
| `explanation` | Why the observation can matter. |
| `limitations` | Benign explanations and what the rule cannot see. |
| `attack` | MITRE ATT&CK techniques as `{id, name}`. |
| `next_step` | Suggested follow-up. |
| `correlation_group` | Findings in the same group are scored once. |

### PE structures

`pe` mirrors the file layout:

- `format` (`pe32` or `pe32_plus`), `dos_header`, `coff_header`, `optional_header`, with every
  field of the corresponding header. Flag fields also come with a `_flags` list of names.
- `data_directories`: `{index, name, rva, size}` for each entry the file declares.
- `section_table` (status) and `sections`. Each section has the header fields, `raw_name` (the
  eight name bytes as hex), `permissions` (e.g. `"R-X"`), `raw_data` (`none`, `full`,
  `truncated` or `outside_file`) and `entropy` (`{entropy, bytes}` or `null`).
- `section_anomalies`: `items` of `{kind, section, other_section, description}` and `truncated`.
- `imports`, `exports`, `resources`, `debug`, `tls`, `certificate`, `overlay`: each with a
  `status` and its entries.
- `issues`: header inconsistencies as `{code, message}`.

## HTML report

The HTML report is one file with its stylesheet inline. It contains no scripts, loads nothing
from the network and links only to its own headings, so it can be opened on an isolated
machine. Every piece of text taken from the analyzed file is escaped, and invalid UTF-8 and
control characters are replaced. As a second layer, the document carries a Content Security
Policy that allows nothing but its inline styles, which stops a browser from running scripts or
fetching resources even if escaping were ever bypassed.

Long lists (imports, exports, resources, strings) are collapsed under expandable headings.
Findings are listed from most to least severe.
