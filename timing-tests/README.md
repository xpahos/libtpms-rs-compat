# tpms-timing-tests

Timing-fuzzing prototype for `TPM2_ECDH_ZGen` on NIST P-521, driven through the public
libtpms ABI of two shared libraries: this repository's Rust implementation and the pinned C
libtpms reference (the `libtpms` submodule commit). LibAFL searches for scalar pairs whose
execution time differs, and the original upstream dudect independently re-measures every
selected pair in fresh worker processes.

## One command (native Linux x86_64)

From any directory:

```sh
python3 timing-tests/run.py
```

The launcher checks prerequisites, builds everything in release mode with `--locked`, and then
runs, in order:

1. deterministic self-tests plus live positive and negative controls;
2. an adaptive search on the Rust library and one on the reference library;
3. independent dudect verification of the combined search candidates, plus labelled boundary
   seed diagnostics, on both libraries;
4. a replay of every candidate selected for verification;
5. the combined JSON and Markdown report.

No library paths, environment variables or run-directory names need to be supplied. Each
invocation writes into its own new evidence directory and refuses to reuse an existing,
non-empty one.

## Prerequisites (Ubuntu 24.04, x86_64)

```sh
sudo apt-get update
sudo apt-get install -y build-essential autoconf automake libtool pkg-config libssl-dev git curl ca-certificates python3
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.95.0
. "$HOME/.cargo/env"
git submodule update --init libtpms
```

Rust 1.95.0 is required (the validated toolchain). With rustup installed the launcher runs
`rustup run 1.95.0 cargo`, so 1.95.0 does not have to be the default toolchain.
The launcher never installs packages, calls `sudo` or changes system settings; when something is
missing it stops before building and prints the command to run.

The first run needs network access: Cargo downloads the locked crates, and the timing tool
downloads `dudect.h` and its `LICENSE` from `raw.githubusercontent.com` at the pinned revision
`dc269651fb2567e46755cfb2a13d3875592968b5` and checks their SHA-256. Later runs reuse the caches.

The dudect timer is `mfence`+`rdtsc`, so only x86_64 hosts can measure. Runs on virtualized or
binary-translated hosts are labelled exploratory in every manifest and in the report.

## Short smoke run

```sh
python3 timing-tests/run.py --max-evaluations 20 --search-duration-s 300 --search-samples 30 \
    --verify-budget 22000 --verify-repeats 2 --verify-time-limit-s 300 --max-verify-candidates 2 \
    --seed-diagnostics 1 --control-verify-budget 22000
```

dudect reports nothing before more than 10000 measurements per class, so verification budgets
below roughly 22000 end as incomplete by design. Keep `--control-search-evaluations` at its
default of 400: the live positive control must find an improving candidate by mutation, which
took about 200-250 evaluations in validation runs, and a smaller budget can fail the control
and stop the pipeline with exit 4.

## Changing parameters

```sh
python3 timing-tests/run.py --seed 7
python3 timing-tests/run.py --max-evaluations 1000 --search-duration-s 3600 --search-samples 200
python3 timing-tests/run.py --verify-budget 200000 --verify-repeats 3 --verify-time-limit-s 1800 --max-verify-candidates 8
python3 timing-tests/run.py --cpu 3
python3 timing-tests/run.py --output-dir /data/timing/run-2026-10-03
```

| Option | Default | Meaning (forwarded unchanged to the Rust CLI) |
|---|---|---|
| `--seed` | 42 | campaign seed for searches, controls and boundary diagnostics |
| `--max-evaluations` | 400 | timed search evaluations per backend |
| `--search-duration-s` | 1800 | search duration limit per backend |
| `--search-samples` | 100 | timed executions per class per search batch (also used by replay) |
| `--verify-budget` | 60000 | dudect measurements per repeat and backend |
| `--verify-batch` | 1000 | measurements per `dudect_main` call (at least 32) |
| `--verify-repeats` | 2 | independent dudect repeats per backend |
| `--verify-time-limit-s` | 900 | wall-clock limit per dudect repeat and backend |
| `--max-verify-candidates` | 16 | search candidates verified, highest search score first |
| `--seed-diagnostics` | 4 | labelled boundary seed pairs added to verification |
| `--control-search-evaluations` | 400 | live control search budget in the self-test |
| `--control-verify-budget` | 40000 | dudect budget per live control repeat |
| `--replay-batches` | 2 | search-style batches per replayed candidate |
| `--operation-timeout-s` | 300 | bound for every single worker operation |
| `--cpu` | highest permitted CPU | CPU the measurement workers are pinned to (`sched_setaffinity`) |
| `--output-dir` | `target/timing-tests/launcher/<UTC>-<pid>` | new evidence directory |
| `--jobs` | permitted CPUs | parallel `make` jobs for the reference build |
| `--build-cache` | `target/timing-tests/native` | shared build cache; safe to share between concurrent invocations |

Invalid options exit with status 2 before any work starts.

## Where artifacts go

Everything is generated below `target/timing-tests/`; the source checkout is not modified.

### Shared build cache (`target/timing-tests/native/`, or `--build-cache`)

- `rust-lib-target/` and `cargo/`: Cargo target directories for the Rust library and the
  timing tool. Cargo decides incremental rebuilds.
- `reference/<key>/`: one immutable entry per effective reference-build configuration (see
  below). An entry is built in a private `.staging-*` directory from a clean `git archive` of
  the pinned submodule commit and published by an atomic rename; it is never modified
  afterwards. An entry whose stamp, library or headers no longer match is moved aside and
  rebuilt.
- `deps/`: checksum-verified dudect sources shared between invocations.
- `locks/`: `flock` lock files. Building, validating, publishing and copying out of a cache
  entry happen while its lock is held, so concurrent invocations build an entry once and never
  observe a half-written one. Waiting for a lock prints a message and can be interrupted with
  Ctrl-C like any other stage.

### Per-invocation evidence (`target/timing-tests/launcher/<run>/`)

- `artifacts/`: private, read-only copies (not hard links) of the Rust library, the reference
  library, the timing tool and the libtpms headers, taken from the cache under its lock before
  any measurement starts. Every later stage uses only these copies, so a concurrent rebuild or
  cleanup of the shared cache cannot change what this invocation executes. Their SHA-256 values
  are recorded in `launcher-summary.json` (`artifacts`) and `environment.json`
  (`artifacts_used`, `binaries`) and re-checked when the invocation finishes; a mismatch fails
  the run.
- `work/`: the timing tool's private work directory. It is seeded with copies of the shared
  dudect sources, and the dudect worker binary is compiled here, so worker binaries are never
  shared between invocations. Newly downloaded dudect sources are published back to the shared
  cache after the self-test.
- `launcher-summary.json`: every stage with commands, working directories, environment,
  start/end times, exit status, run directories, artifact hashes, the aggregate outcome and
  explanations. It is rewritten after every step and finalized on every exit path, including
  failures, interruptions and launcher errors.
- `environment.json`: repository revision and dirty files, source digests, artifact hashes,
  toolchain, OpenSSL, platform, CPU and effective parameters.
- `logs/NN-<stage>.log`: complete output of every command.
- `runs/NN-<stage>/<run>/`: the timing tool's own run directory for that stage.
- `report/report.json` and `report/report.md`: the combined report, claimed only after it has
  been read back and validated.

Concurrent invocations may share the build cache, but they still share CPUs; run measurements
one at a time if timing noise matters.

### Reference build environment and cache identity

The reference library is built with an environment constructed from scratch: `PATH`, `HOME`,
`TMPDIR`, `LC_ALL=C`, `LANG=C`, plus these supported settings when they are set:

`CC`, `CFLAGS`, `CPPFLAGS`, `LDFLAGS`, `PKG_CONFIG_PATH`, `PKG_CONFIG_LIBDIR`,
`PKG_CONFIG_SYSROOT_DIR`.

Other variables that would influence autotools or the compiler (for example `CXX`, `CPP`,
`LIBS`, `LD`, `AR`, `MAKEFLAGS`, `CONFIG_SITE`, `CPATH`, `LIBRARY_PATH`, `LD_LIBRARY_PATH`,
`OPENSSL_DIR`) are not passed to the build; the ones found are listed as `normalized_away`.
`CC` is split like a shell word list, so quote compiler paths that contain spaces
(`CC="'/opt/my gcc/bin/gcc' -m64"`, `CC="env '/opt/my gcc/bin/gcc'"`).

Supported `CC` forms:

| Form | Example | Identified as |
|---|---|---|
| compiler executable with option arguments | `gcc`, `'/opt/my gcc/bin/gcc' -m64` | the executable found on `PATH` (or the absolute path) |
| `env [NAME=VALUE ...] <compiler> [options]` | `env /usr/bin/gcc-13`, `env PATH=/opt/gcc/bin gcc` | `env` plus the compiler `env` would run, resolved with the assignments applied |
| `ccache <compiler> [options]` | `ccache gcc` | `ccache` plus the first matching compiler on `PATH` that is not ccache itself |

For wrapper forms both the wrapper and the effective compiler are fingerprinted (resolved path,
real path, SHA-256 and `--version`), together with the arguments and `env` assignments, so
replacing the compiler behind a wrapper selects a new cache entry. The launcher rejects in
preflight, before compiling anything or using any cache entry (the reference build stage checks
again before touching the cache): other wrappers (`distcc`, `sccache`, `icecc`, `nice`, `time`,
shells, ...), nested wrappers, `env` options, words after the compiler that are not options,
relative paths, compilers that resolve to a wrapper (for example `/usr/lib/ccache/gcc` on
`PATH`), and compilers that are scripts, because a script can run a compiler the key cannot see.
The effective compiler's identity is recorded under `fingerprint.compiler` in the reference
build stage.

Nothing downstream re-parses the `CC` string. From the parsed configuration the launcher
generates a compiler launcher, a two-line `/bin/sh` file that runs exactly the fingerprinted
argument vector with every word quoted, for example
`exec /usr/bin/env 'CPATH=/opt/x y' '/opt/my gcc/bin/gcc' -m64 "$@"`. Wrapper and compiler
appear as resolved absolute paths, followed by the `env` assignments and the options from `CC`.
The launcher is content-addressed and read-only under `<build cache>/compilers/<sha256>/cc`,
with a `launcher.json` that records the original `CC`, the form and the argument vector. Its hash
and argument vector are part of the cache key; the stage records them under
`build_configuration.compiler_launcher`. Every compilation uses it:
- `configure` and `make` get it as `CC` through a whitespace-free path, so Autoconf's word
  splitting of `$CC` cannot change it. This also applies when `CC` is unset: the reference
  build then uses the fingerprinted `cc` instead of letting `configure` search for `gcc` first.
- When `CC` is set, Cargo builds (the `cc` crate treats an existing path as one program) and the
  timing tool's dudect worker compile get the same launcher path as `CC`.

Preflight resolves and publishes the launcher; the reference stage resolves `CC` again and fails
if it no longer maps to the same launcher. If `RUSTC_WRAPPER` is set, the `cc` crate may also
use it around the compiler in Cargo builds; Cargo decides when those builds are rerun.

The cache key is a SHA-256 over: the pinned commit, the configure flags, the supported settings,
the selected compiler (resolved path, binary hash and `--version`) and the generated compiler
launcher, the libcrypto and libssl
`pkg-config` results (version, cflags, libs, libdir, includedir) with the hashes of
`libcrypto.so`, `libssl.so` and `opensslv.h`, and the paths, hashes and versions of `make`,
`autoreconf`, `automake`, `libtoolize`, `pkg-config` and `sh`. Changing any of them selects a
different entry; unchanged inputs reuse the existing one. The exact environment given to
`autogen.sh`, `configure` and `make`, the fingerprint and the key are recorded in the build
stage of `launcher-summary.json`.

## Exit status and verdicts

| Exit | Meaning |
|---|---|
| 0 | completed: every stage ran and every verified candidate has a definite result |
| 3 | incomplete: some verification was inconclusive (mixed or missing repeats, insufficient measurements, time limits) or the run was interrupted |
| 4 | failed: a prerequisite, build, control, functional or infrastructure check failed; failure wins over incomplete |
| 2 | invalid launcher arguments |

A failed self-test or control stops the timing stages that depend on it; skipped stages are
listed with their reason. The live positive-control *search* check passes only when mutation
finds a pair that beats the best seed pair by the configured improvement margin; on noisy or
emulated hosts this check has failed at the default budget (observed with seed 42 under
Rosetta). Such a failure means the pipeline could not demonstrate its own search sensitivity on
that host; it is not a verdict about either libtpms library. Incomplete verification still produces replays and the report.
A signal only cancels a command that is still running. When a signal arrives, the launcher checks
whether the command's main process has already exited, using a non-reaping `waitid(WNOWAIT)` or
the exit status `wait()` already returned. A command still running at that point is stopped and
counts as cancelled (`cancelled_by_signal: true`, incomplete). A command that had already exited
keeps its observed status (`signal_after_exit: true`), so a failure that completed before the
signal still makes the run fail (exit 4), even when the signal lands right after `wait()` returned.
Descendants left behind by an exited command are still stopped through its process group, and
are reported as leftover processes (a failure).
Ctrl-C or SIGTERM stops the running command's whole process group (or the wait for a build-cache
lock), keeps all logs and partial run directories and finishes the summary as incomplete (or
failed, if a failure had already occurred); this also holds when the signal arrives just before
or during report generation. A report command that fails, or writes a report that cannot be read
back as a valid report, fails the run and no report is claimed. If the evidence directory itself
becomes unwritable, the launcher prints the error and the outcome it had reached and exits with
status 4. The launcher never retries a measurement to obtain a different verdict.

How to read the report:

- **Search score** (relative median difference with a Welch-t gate) only ranks candidates; it is
  not evidence of leakage.
- **Reproducible timing signal**: every independent dudect repeat in fresh processes crossed
  dudect's own threshold for that backend. It is a measurement result, not an infrastructure
  failure, and it is not attributed to secret data alone (each class also loads a different
  public key and returns a different shared point).
- **No signal detected within budget**: dudect exhausted a sufficient, finite budget without
  crossing its threshold. This is not a constant-time or equivalence claim.

## Scope

Only the warmed `TPM2_ECDH_ZGen` command on P-521 with a fixed peer point is measured; key
generation, key loading, first use and other commands are excluded. Absolute Rust and C
execution times are never compared; each library is judged on its own class-to-class timing
dependence.

## Lower-level commands

The launcher wraps the `tpms-timing-tests` CLI (`self-test`, `search`, `verify`, `replay`,
`report`; see `--help`). The package's own checks:

```sh
cd timing-tests && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
python3 -m unittest discover -s timing-tests/pytests -v
```

The launcher tests use fixtures in place of the real libraries and the timing tool. Two kinds of
test run real programs:
- The compiler-execution tests run a small autoconf project in `pytests/fixtures/mini-libtpms`
  through the same `autogen.sh`, `configure` and `make` steps as the reference build, using a real
  compiler reached through a path that contains spaces. They are skipped when `cc`, `make` or
  `autoreconf` is missing.
- The signal-ordering tests deliver a real SIGINT at fixture points such as `after-wait:<stage>`,
  which falls after `wait()` has returned and before the launcher releases the command.
