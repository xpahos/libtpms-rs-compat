# External TPM validation

Requires **Python 3** and a running **Docker** daemon. Run commands from the
repository root. Sources are downloaded and all builds and tests run in Docker.

## Run tests

```sh
# All suites against Rust (default).
python3 external-validation/run.py run

# Reference C libtpms, or both implementations with a comparison.
python3 external-validation/run.py run --backend reference
python3 external-validation/run.py run --backend both

# One suite, or one Microsoft scenario against both implementations.
python3 external-validation/run.py run --backend both tpm2-tools
python3 external-validation/run.py run --backend both --filter TestRandom microsoft-tss

# Validation framework tests, including bridge ABI checks against both libraries.
python3 external-validation/run.py self-test
```

Available suites: `tpm2-tss`, `tpm2-tools`, `google-go-tpm`,
`canonical-go-tpm2`, `microsoft-tss`. Pass one or more names; omitting them runs all.

`--filter` requires exactly one suite:

- **tpm2-tss / tpm2-tools:** Python regex over test basenames.
- **Google / Canonical Go:** Go test-name regex. Canonical's individual gocheck
  methods cannot be selected; they run together under `Test`.
- **Microsoft:** exact test, profile or category names, such as `TestRandom`.

## Run options

| Option | Purpose |
| --- | --- |
| `--library PATH` | Test an existing Linux `libtpms.so`; cannot be combined with `--backend`. |
| `--prepare-only` | Download and build suites without running tests; cannot be combined with `--filter`. |
| `--no-build-image` | Reuse the previously built Docker image. |
| `--image NAME` | Choose a Docker image tag; default `libtpms-external-validation:local`. |
| `--jobs N` | Parallel build jobs; default: container CPU count. |
| `--timeout SECONDS` | Timeout per preparation, library build or suite run; default `1800`. |
| `--microsoft-test-timeout SECONDS` | Timeout per Microsoft scenario; default `120`. |

Use `python3 external-validation/run.py COMMAND --help` for all options.

## Results

The command prints the result directory:
`target/external-validation/results/RUN_ID/`.

- `summary.txt`: overall result and failures.
- `rust/`, `reference/` or `selected/`: per-backend `results.json` and suite logs.
- `comparison.json`: comparison when running with `--backend both`.

To inspect saved results without Docker, replace `RUN_ID` below:

```sh
python3 external-validation/run.py report target/external-validation/results/RUN_ID
python3 external-validation/run.py compare \
  target/external-validation/results/RUN_ID/reference \
  target/external-validation/results/RUN_ID/rust
```

Downloads and build caches are stored in `target/external-validation/cache/`.
Set `EXTERNAL_VALIDATION_WORK_DIR` to change the directory containing `cache/`
and `results/`.

For test runs, `report` and `compare`, exit code `0` requires successful,
complete validation. Failed, skipped or incomplete validation returns `1`;
usage errors return `2`. Matching failures on C and Rust remain unsuccessful.
With `--prepare-only`, exit code `0` means preparation succeeded; no tests ran.
