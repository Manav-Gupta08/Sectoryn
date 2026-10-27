# Benchmarks

`benchmarks/bench_analysis.cpp` times each analysis stage on synthetic PE files and a batch of
files. Inputs are generated deterministically (half pseudo-random bytes, half text with
embedded paths and registry keys), so runs on different machines analyze identical data.

```sh
cmake --preset linux-release -DSECTORYN_BUILD_BENCHMARKS=ON
cmake --build --preset linux-release --target sectoryn_bench
./build/linux-release/bin/sectoryn_bench 5      # repetitions per measurement
```

Files are written to the system temporary directory and read back through the normal
`FileReader`, so the page cache is warm after the first repetition. The median is the figure to
compare; "best" shows the noise floor.

## Results

Intel Core i7-9700 (8 cores, 3.0 GHz), 16 GB RAM, ext4, Ubuntu 24.04, kernel 7.0,
GCC 13.3, `-O3`, default limits, 5 repetitions.

| Stage | Input | Median (ms) | Best (ms) | MiB/s (median) |
|---|---|---|---|---|
| SHA-256 | 1 MiB | 2.0 | 2.0 | 498 |
| PE parsing | 1 MiB | 0.1 | 0.1 | 10877 |
| Entropy | 1 MiB | 3.6 | 3.4 | 277 |
| Strings | 1 MiB | 11.5 | 10.6 | 87 |
| Full analysis | 1 MiB | 26.2 | 25.4 | 38 |
| SHA-256 | 16 MiB | 32.3 | 31.9 | 496 |
| PE parsing | 16 MiB | 6.5 | 4.0 | 2462 |
| Entropy | 16 MiB | 27.2 | 26.6 | 588 |
| Strings | 16 MiB | 87.6 | 85.1 | 183 |
| Full analysis | 16 MiB | 242.6 | 229.6 | 66 |
| SHA-256 | 64 MiB | 130.4 | 130.2 | 491 |
| PE parsing | 64 MiB | 37.0 | 36.6 | 1731 |
| Entropy | 64 MiB | 102.2 | 101.1 | 626 |
| Strings | 64 MiB | 90.8 | 84.8 | 705 |
| Full analysis | 64 MiB | 479.2 | 468.9 | 134 |

Batch of 32 distinct 4 MiB files:

| Workers | Wall time (ms) | Files/s |
|---|---|---|
| 1 | 3463 | 9.2 |
| 2 | 1773 | 18.1 |
| 4 | 974 | 32.9 |

Peak resident memory for the whole benchmark run: 239 MiB.

## Reading the numbers

* **Strings** at 64 MiB is faster than at 16 MiB because extraction stops at the default limit
  of 100,000 strings; the result is marked incomplete. The synthetic data is unusually dense in
  strings. The 16 MiB figure is the representative throughput.
* **Full analysis** is more than the sum of the stages for small files because indicator
  classification and rule evaluation run per string, not per byte.
* **SHA-256** reaches about 95% of `openssl speed -evp sha256` with 64 KiB blocks on the same
  machine (521 MiB/s), so file reading and buffer handling are not the bottleneck and no buffer
  pooling is used.
* **Batches** scale close to linearly up to 4 workers because each job is CPU-bound and reads its
  file independently. The default is 2 workers so that interactive use stays responsive.
* **Memory** is dominated by the one copy of the file held during parsing (bounded by
  `max_file_bytes`) and by the extracted strings (bounded by `max_strings` and
  `max_string_bytes`). Hashing, entropy and string extraction stream in `read_chunk_bytes`
  chunks.
