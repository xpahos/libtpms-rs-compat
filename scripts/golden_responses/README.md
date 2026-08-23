# Golden response tests

These tests check that the Rust TPM behaves exactly like the reference C
implementation in `libtpms/`.

For each test family, we:

1. Run a scenario against libtpms in a deterministic Docker container.
2. Save the responses and selected TPM state blobs in a binary fixture.
3. Replay the same commands in Rust.
4. Compare the Rust output with the saved bytes.

The full path is:

```text
scenario -> reference libtpms -> binary fixture -> Rust test
```

The `.bin` fixtures are generated files. Do not edit or merge them by hand.

## The commands you will normally use

Check the repository metadata and fixture structure:

```sh
make golden-audit
```

This check is fast, does not use Docker, and does not change files. Normal
`make build` and `make build-release` run it automatically.

Re-run every scenario against libtpms and compare the result with the committed
fixtures:

```sh
make test-golden
```

This uses Docker, but does not change fixtures.

Regenerate one fixture after an intentional scenario change:

```sh
make update-golden FAMILY=create-primary
```

Regenerate all fixtures after intentionally updating libtpms or the capture
environment:

```sh
make update-golden-all
```

Updating every family is deliberately harder to do by accident. The underlying
command requires `--confirm-reference-update`; the Make target supplies it.

## Typical workflows

### You changed the Rust implementation

Run:

```sh
make golden-audit
cargo test
make test-golden
```

If a golden test fails but neither the scenario nor reference libtpms changed,
the committed fixture is still the expected answer. Fix the Rust code. Do not
regenerate the fixture just to make the test pass.

### You changed a scenario

First inspect which records changed, then regenerate that family:

```sh
python3 scripts/golden_responses/golden.py diff <family>
make update-golden FAMILY=<family>
make test-golden
```

Commit the scenario and fixture changes together.

### You updated libtpms or the capture image

Run:

```sh
make update-golden-all
make ci
```

Review every changed family. A reference update may also require changes in the
Rust implementation and its tests.

### A golden test does not match

Show a short list of changed records:

```sh
python3 scripts/golden_responses/golden.py diff create-primary
```

Print all records, or one selected record, as hexadecimal bytes:

```sh
python3 scripts/golden_responses/golden.py dump create-primary
python3 scripts/golden_responses/golden.py dump create-primary RECORD_NAME
```

## Command-line interface

The Make targets call `golden.py`. It can also be used directly:

```sh
python3 scripts/golden_responses/golden.py <command>
```

| Command | Purpose |
| --- | --- |
| `audit` | Check metadata, scenarios, readers, and fixtures without Docker. |
| `build` | Audit the repository, then build or reuse the reference image and validate it. |
| `verify <family>` | Capture one family and compare it with its fixture. |
| `verify --all` | Capture and compare every family. |
| `update <family>` | Capture one family and replace its fixture safely. |
| `update --all --confirm-reference-update` | Capture and replace every fixture. |
| `diff <family>` | List records that differ from a fresh reference capture. |
| `dump <family> [record]` | Print fixture records as hexadecimal text. |
| `list` | List families, files, record counts, and covered TPM commands. |

The corresponding public Make targets are:

```text
make golden-audit
make test-golden
make update-golden FAMILY=<name>
make update-golden-all
make ci
```

## Files in this directory

- `manifest.toml` lists the families and connects each scenario to its fixture,
  Rust reader, magic value, and TPM commands.
- `scenarios/*.scenario` contains the command sequences sent to libtpms.
- `runner.c` reads scenarios and calls libtpms.
- `fixture_format.py` reads and writes the binary fixture format.
- `Dockerfile` builds the reference environment.
- `entropy_shim.c` makes entropy and clocks deterministic during capture.
- `golden.py` provides the audit, capture, comparison, and update commands.

Generated fixtures live in:

```text
src/library/tpm2/testdata/golden_responses/*.bin
```

Rust fixture readers live in:

```text
src/library/tpm2/golden_responses/*.rs
```

Every fixture has exactly one scenario. There is no second generator or hidden
capture path.

## Scenario format

A scenario is a small text program. Its saved output consists of named records:

```text
RECORD_NAME hexadecimal-bytes
```

The fixture writer sorts records by name before writing the `.bin` file. This
keeps the fixture stable when the scenario produces the same results.

Supported operations:

| Operation | What it does |
| --- | --- |
| `profile <json>` | Erase NVRAM and manufacture a TPM with this profile. |
| `send NAME <hex>` | Send a TPM command and save the complete response as `NAME`. |
| `raw <hex>` | Send a command without saving its response. |
| `permall NAME` | Save the current permanent-state blob. |
| `snapshot NAME` | Save permanent and volatile state as records and remember both for `restore`. |
| `checkpoint NAME` | Remember permanent and volatile state without adding fixture records. |
| `restore NAME` | Restore both state blobs from a snapshot or checkpoint. |
| `restore-permanent NAME` | Restore only permanent state. |
| `reboot` | Reinitialize the TPM while keeping NVRAM. |
| `advance <ms>` | Move the deterministic TPM clock forward. |
| `locality <n>` | Change the locality returned by the platform callback. |
| `remember-session` | Treat the previous response as the authorization session used by later helpers. |
| `audited-getrandom NAME` | Run `TPM2_GetRandom` through the remembered session. |
| `exclusive-audit NAME` | Save the exclusive-audit value from volatile state. |
| `fail-stores <0\|1>` | Turn simulated NVRAM write failures on or off. |
| `patch-failure-code <n>` | Replace the saved failure-mode code and restore the state. |
| `version` | Save the libtpms version. |

Record names may contain upper-case ASCII letters, digits, and underscores.
By convention:

- `PERMALL_*` contains permanent state;
- `VOLATILE_*` contains volatile state;
- other records contain TPM responses or small values emitted by the runner.

`golden-audit` checks scenario syntax before Docker starts. It rejects unknown
operations, invalid arguments, duplicate records, invalid checkpoint use, and
families whose scenarios do not send the commands claimed in `manifest.toml`.
Malformed TPM packets are allowed because error handling also needs coverage.
A packet with a truncated TPM header does not count as command coverage.

## Reusing bytes produced by an earlier command

Some commands need opaque data produced by another command. For example:

- `TPM2_Load` needs `outPrivate` returned by `TPM2_Create`;
- `TPM2_ContextLoad` needs a blob returned by `TPM2_ContextSave`;
- parameter encryption needs the `nonceTPM` chosen when the session started.

Scenario files are static, so these values are pasted into the scenario as
hexadecimal bytes. This remains reproducible because the reference container is
deterministic.

Keep such sections independent:

1. Start every section that consumes a captured blob with `restore`.
2. Keep the producing command as a named `send` record.
3. Let the Rust test read the produced value from that fixture record instead
   of copying it into Rust code.

To add a new section:

1. Append the producing command and update the fixture.
2. Use `dump` to obtain the produced bytes.
3. Paste those bytes into the consuming command.
4. Update and verify the fixture again.

The `object-lifecycle` family uses this pattern. So does `rsa-encryption`: its
`DEC_*` records consume the ciphertext returned by an earlier `ENC_*` record,
and its authorized and parameter-encrypted sections consume the `nonceTPM` and
the object name returned when the session and the key were created.

## Scenarios that reset or destroy state

Commands such as `TPM2_Clear` and `TPM2_ChangePPS` remove or replace state that
later checks may need. The `hierarchy-management` scenario therefore consists
of independent sections. Each destructive section starts with:

```text
restore READY
```

`snapshot READY`, taken immediately after `TPM2_Startup(TPM_SU_CLEAR)`, saves
both permanent and volatile reference state. Restoring both is important: the
volatile blob includes the reference DRBG state. After a restore, commands such
as `TPM2_CreatePrimary` produce the same key bytes again.

Commands that replace hierarchy seeds create new state that cannot be compared
with a separately manufactured Rust TPM. Instead, the scenario checks their
effects through normal TPM commands:

- `TPM2_GetCapability` checks flags, handles, and dictionary-attack properties;
- `TPM2_PCR_Read` checks the PCR update counter;
- `TPM2_NV_ReadPublic` and `TPM2_ReadPublic` check which entities remain;
- `TPM2_Shutdown(TPM_SU_STATE)` followed by `TPM2_Startup(TPM_SU_STATE)` checks
  whether a command cleared orderly state.

The final `hierarchy-management` section uses the `null` profile to cover the
old state format. This also preserves a compatibility detail in libtpms:

- state format level 1 stores persistent objects in the legacy layout;
- level 2 and newer store them as `ANY_OBJECT`;
- `NvFlushHierarchy()` still reads hierarchy attributes at the old offset;
- in an `ANY_OBJECT` entry, that offset contains header bytes, so persistent
  objects are not deleted by `TPM2_ChangeEPS`, `TPM2_ChangePPS`, or
  `TPM2_Clear`.

The `LEGACY_*` records cover the level-1 result. The `PPS_*` and `CLR_*` records
cover the newer format. This odd behavior is intentional compatibility with the
vendored libtpms, not a fixture mistake.

## Why captures are reproducible

A normal TPM manufacture uses random entropy and the system clocks. Without
extra controls, two containers would produce different fixtures.

The reference image removes those differences:

- `entropy_shim.c` replaces OpenSSL random bytes with a deterministic stream
  seeded by `GOLDEN_ENTROPY_SEED`;
- the shim freezes monotonic and CPU clocks until the scenario advances them;
- libfaketime freezes wall-clock time;
- the base image, Debian snapshot, packages, compiler flags, libtpms commit,
  target platform, entropy seed, and clock settings are pinned.

The deterministic random generator is only used while creating test fixtures.
It is not secure and is never used by the Rust library in production.

Before a capture starts, `golden.py` validates the image, package versions,
platform, clock behavior, and entropy behavior. It also runs the same probe in
two fresh containers and requires identical output.

## How the Docker image is cached

`golden.py` creates a temporary Docker build context from:

- tracked files under `scripts/golden_responses/`, except `manifest.toml`;
- `git archive HEAD` from the `libtpms` submodule.

Untracked files, build output, and submodule `.git` data cannot enter the image.
The context and target platform are hashed. That hash is stored in both the
image tag and the `golden.identity` label. An existing image is reused only when
both its identity and platform match.

`manifest.toml` is not part of the image hash because it describes how scenarios
and fixtures use the image; it does not change the reference executable. The
audit validates the manifest separately.

Only submodules included in the Docker context must be clean. Currently this is
only `libtpms`. Changes in `swtpm` belong to the separate swtpm test workflow.

## What `golden-audit` checks

The audit works without Docker and never writes files. It verifies, among other
things, that:

- manifest paths are valid and stay inside the repository;
- every declared scenario, fixture, and Rust reader exists and is tracked;
- fixtures are structurally valid and use the declared magic value;
- each Rust reader opens the correct fixture with the correct magic;
- fixture paths, magic values, and TPM command ownership are unique;
- implemented commands agree with the upstream table and Rust registry;
- scenarios actually send the commands they claim to cover;
- reference-image inputs and pins have not drifted.

Reader checks inspect the `magic` and `include_bytes!` values in the same
`Fixture::new` declaration. Test-only declarations do not count. If the audit
cannot parse a relevant declaration safely, it fails instead of guessing.

Commands that use Docker (`build`, `verify`, `update`, and `diff`) run this
audit first and then validate the resolved image.

## How fixture updates avoid partial changes

An update captures every selected family before replacing any fixture. It then:

1. Creates backups and prepares all replacement files.
2. Installs each replacement atomically with `os.replace`.
3. Reads every new fixture back and validates it.
4. Removes backups and temporary files after the whole update succeeds.

If capture, replacement, validation, or `Ctrl-C` fails before completion, the
tool restores every fixture it already replaced. Newly created fixtures are
removed. Existing file modes are preserved.

If a backup cannot be restored, the tool keeps it and prints its path for manual
recovery. A cleanup error after a successful update does not undo valid new
fixtures.

`audit`, `verify`, and `diff` never change fixture files.

## Resolving fixture merge conflicts

Never merge the raw bytes of a `.bin` file. Resolve conflicts in the scenario,
manifest, and reference inputs first. Then temporarily choose either binary
side and regenerate the fixture:

```sh
python3 scripts/golden_responses/golden.py update <family>
python3 scripts/golden_responses/golden.py verify --all
```

Use `dump` and `diff` to understand a fixture, not to assemble one manually.

## How these tests fit into the repository

The test layers have different jobs:

1. `cargo test` checks Rust functions, state transitions, and invariants.
2. Golden tests compare deterministic Rust output byte-for-byte with libtpms.
3. `make test-swtpm` checks the Rust library as a replacement `libtpms.so` in a
   complete swtpm workflow.

Cancellation, control-channel behavior, and concurrency remain in the swtpm
suite because they depend on process interaction rather than a deterministic
sequence of TPM commands.
