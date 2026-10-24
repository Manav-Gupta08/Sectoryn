# Entropy

Sectoryn reports Shannon entropy for the whole file, for each section's raw data, for the
overlay, and as a profile across the file. This page describes how the numbers are computed and
what they can and cannot tell you.

## Method

For a byte range of length *n* in which byte value *i* occurs *c<sub>i</sub>* times:

```
p_i = c_i / n
H   = -sum(p_i * log2(p_i))   over all i with c_i > 0
```

*H* is measured in bits per byte and lies between 0 (one value repeated) and 8 (all 256 values
equally frequent). Empty ranges are reported as having no entropy value, not as 0.

The implementation (`src/analysis/Entropy.cpp`, `ByteStatistics.cpp`) builds a 256-entry
histogram while streaming the file in fixed-size chunks, so memory use does not depend on file
size. Results are clamped to [0, 8] to absorb floating-point rounding.

### Ranges

| Range | Bytes measured |
|---|---|
| File | Every byte of the file |
| Section | The part of `PointerToRawData`..`+SizeOfRawData` that exists in the file. Sections with no raw data have no value. |
| Overlay | From the end of the last section's raw data to the end of the file |
| Profile | Consecutive blocks of at least 256 bytes, sized so the file yields at most 1024 points |

Section entropy is measured over the bytes as stored in the file, not over the image the loader
would build in memory. Zero padding added by the loader is not included.

### Resource bounds

Sections may overlap, so measuring each one separately could mean reading the file many times.
The total number of section bytes read is capped at twice the file size. Sections beyond that
budget are reported as skipped rather than given a value.

## Interpreting the values

Typical ranges, which overlap and should be read as rough guides only:

| Content | Usual entropy |
|---|---|
| Zero-filled or highly repetitive data | 0 – 1 |
| Text, resources, uncompressed data | 3 – 5 |
| Compiled x86/x64 code | 5.5 – 6.8 |
| Compressed or encrypted data | 7.5 – 8 |

## Limitations

- **High entropy is not evidence of malice.** Compressed resources, images, installers,
  embedded archives, certificates, and legitimate packers all produce values close to 8.
- **Low entropy is not evidence of safety.** Encrypted payloads can be encoded (for example as
  base64 or with a simple XOR on text) to keep entropy moderate.
- **Small ranges are unreliable.** A 64-byte range cannot exceed 6 bits per byte even if it is
  random, because it holds at most 64 distinct values. Rules ignore ranges that are too small to
  be meaningful.
- **Averages hide structure.** A section that is half code and half encrypted data averages to a
  middling value. The profile view exists to show such local changes.
- Entropy is one input to the detection rules. It never decides a triage outcome on its own.
