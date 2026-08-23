# Golden response tests

This directory contains compatibility tests for the Rust TPM implementation.
The tests answer a simple question:

> Given the same TPM state and the same command, does the Rust implementation
> return exactly the same bytes as the reference C implementation?

The reference implementation is the unmodified `libtpms/` submodule. We run it
in a deterministic Docker container, save its responses and state blobs as
binary fixtures, and replay those fixtures from Rust tests.

The data flow is:

```text
scenario -> reference libtpms container -> binary fixture -> Rust test
```

Fixtures are generated files. Do not edit or merge them by hand.

## Quick start

Run the fast repository audit:

```sh
make golden-audit
```

Run every scenario against the reference container and check that the output
still matches the committed fixtures:

```sh
make test-golden
```

Regenerate one fixture after intentionally changing its scenario or reference:

```sh
make update-golden FAMILY=create-primary
```

Regenerate every fixture after an intentional reference update:

```sh
make update-golden-all
```

The direct CLI refuses an all-family update without
`--confirm-reference-update`. The Make target supplies that flag explicitly.
This is deliberate: changing every reference result should never happen by
accident.

## When to use each command

The public interface is `golden.py`:

```sh
python3 scripts/golden_responses/golden.py <command>
```

| Command | What it does |
| --- | --- |
| `audit` | Checks repository metadata and fixtures. Fast, does not run Docker, and does not write files. |
| `build` | Audits the repository, then finds or builds the reference image and validates it. |
| `verify <family>` | Captures one family and compares it with the committed fixture. Does not write. |
| `verify --all` | Verifies every family. Does not write. |
| `update <family>` | Captures one family and safely replaces its fixture. |
| `update --all --confirm-reference-update` | Captures all families before replacing any fixture. |
| `diff <family>` | Shows which named records differ without changing files. |
| `dump <family> [record]` | Prints a fixture as `NAME <hex>` records. |
| `list` | Lists families, record counts, scenarios, fixtures, and covered commands. |

The Make targets are wrappers around these commands:

```text
make golden-audit
make test-golden
make update-golden FAMILY=<name>
make update-golden-all
make ci
```

Normal `make build` and `make build-release` run the static audit first. They do
not require Docker.

## Common workflows

### Checking a Rust change

Run:

```sh
make golden-audit
cargo test
make test-golden
```

If `verify` reports a byte difference and the reference inputs did not change,
the committed fixture remains the expected result. Fix the Rust behavior; do
not update the fixture just to make the test pass.

### Changing a scenario

After intentionally changing a `.scenario` file:

```sh
python3 scripts/golden_responses/golden.py diff <family>
make update-golden FAMILY=<family>
make test-golden
```

Review the fixture change together with the scenario change.

### Updating libtpms or the capture environment

Update the `libtpms` submodule and/or the pinned inputs in `Dockerfile`, then
run:

```sh
make update-golden-all
make ci
```

This is a reference update, so review every changed family. The Rust tests may
also need changes if the new reference behavior is different.

### Scenarios that replay captured blobs

Some commands only accept opaque bytes that an earlier command produced:
`TPM2_Load` needs the `outPrivate` of a `TPM2_Create`, `TPM2_ContextLoad` needs
the blob a `TPM2_ContextSave` returned, and a parameter-encrypted command needs
the `nonceTPM` the reference chose for its session. A scenario is static text,
so those bytes are pasted into it as literal hex.

That is safe because the reference container is deterministic: the same command
prefix always produces the same bytes. The `object-lifecycle` scenario is built
that way, and the ordering rule that keeps it reproducible is:

- every section that consumes a captured blob starts with `restore`, so adding
  such a section never shifts the state of the section that produced the blob;
- the producing command keeps its own `send` record, so the Rust tests read the
  blob back out of the fixture instead of hard-coding it a second time.

To extend such a family, append the new section, run `update`, `dump` the
producing record, paste the new bytes, and run `update` again.

### Investigating a mismatch

Use `diff` for a short record-level summary:

```sh
python3 scripts/golden_responses/golden.py diff create-primary
```

Use `dump` when you need the actual bytes:

```sh
python3 scripts/golden_responses/golden.py dump create-primary
python3 scripts/golden_responses/golden.py dump create-primary RECORD_NAME
```

## What is stored where

- `manifest.toml` connects each family to its scenario, fixture, Rust reader,
  magic value, and covered TPM commands.
- `scenarios/*.scenario` describes what the reference TPM should do.
- `runner.c` interprets scenarios and calls the reference libtpms.
- `fixture_format.py` converts named records to and from the binary fixture
  format.
- `src/library/tpm2/testdata/golden_responses/*.bin` contains the generated
  fixtures.
- `src/library/tpm2/golden_responses/*.rs` loads those fixtures for Rust tests.
- `Dockerfile` defines the reference build environment.
- `entropy_shim.c` makes entropy and TPM time deterministic during capture.

Every fixture has exactly one tracked scenario. There is no legacy generator
or alternate capture path.

## Scenarios

A scenario is a small text program. The runner prints named records in this
form:

```text
NAME hexadecimal-bytes
```

The fixture packer sorts the records by name, so the same scenario output
always produces the same binary file.

Available operations are:

| Operation | Meaning |
| --- | --- |
| `profile <json>` | Clear NVRAM and manufacture a TPM with the given profile. |
| `send NAME <hex>` | Send a TPM command and save its response as `NAME`. |
| `raw <hex>` | Send a command without saving the response. |
| `permall NAME` | Save the permanent-state blob. |
| `snapshot NAME` | Save and remember permanent and volatile state. |
| `checkpoint NAME` | Remember both state blobs without writing records. |
| `restore NAME` | Restore permanent and volatile state from a checkpoint. |
| `restore-permanent NAME` | Restore only permanent state. |
| `reboot` | Terminate and initialize the TPM while keeping NVRAM. |
| `advance <ms>` | Advance deterministic TPM time. |
| `locality <n>` | Change the locality reported by the platform callback. |
| `remember-session` | Remember the last response as an authorization session. |
| `audited-getrandom NAME` | Run `TPM2_GetRandom` through that session. |
| `exclusive-audit NAME` | Save the exclusive-audit value from volatile state. |
| `fail-stores <0\|1>` | Enable or disable simulated NVRAM write failures. |
| `patch-failure-code <n>` | Change the saved failure-mode code and restore it. |
| `version` | Save the libtpms version. |

Record names use upper-case ASCII letters, digits, and underscores:

- `PERMALL_*` records contain permanent state;
- `VOLATILE_*` records contain volatile state;
- all other records contain complete TPM responses or small values explicitly
  emitted by the runner.

The static audit checks scenario syntax before Docker runs. It rejects unknown
operations, bad arguments, duplicate record names, invalid checkpoint use, and
families that claim a TPM command their scenario never sends.

Some scenarios intentionally send malformed TPM packets. Such packets are
valid scenario input, but a truncated header cannot count as command coverage.

## Why the container is deterministic

TPM manufacturing uses random entropy, and libtpms reads system clocks. A
normal container would therefore produce different state blobs on different
runs.

The capture image removes those sources of variation:

- `entropy_shim.c` replaces OpenSSL random-byte calls with a deterministic
  stream seeded by `GOLDEN_ENTROPY_SEED`;
- the same shim freezes monotonic and CPU clocks until a scenario explicitly
  advances them;
- libfaketime freezes the wall clock;
- the Docker base image, Debian snapshot, packages, compiler flags, libtpms
  commit, target platform, entropy seed, and clock settings are pinned.

The deterministic random stream is only a test tool. It is not cryptographically
secure and is never used by the Rust library in production.

Before capture, image validation checks the compiled clock and entropy behavior,
the installed package versions, the platform, and the image identity. It also
runs a probe scenario in two fresh containers and requires identical output.

## How the reference image is identified

`golden.py` builds its own temporary Docker context from:

- tracked files under `scripts/golden_responses/`, except `manifest.toml`;
- a `git archive HEAD` of the `libtpms` submodule.

Untracked build products, ignored files, and submodule `.git` data cannot enter
the image. The context contents and target platform are hashed, and the hash is
stored both in the image tag and its `golden.identity` label. An image is reused
only when its label and platform match.

`manifest.toml` is intentionally not part of the image hash. It describes how
the image and fixtures are expected to fit together; the audit checks those
claims independently.

Only submodules included in the context must be clean. Currently that is
`libtpms`. Changes inside `swtpm` do not affect golden capture and are checked by
the separate swtpm test workflow.

## What the audit checks

`golden.py audit` is a static check. It works on a fresh checkout without Docker
and never modifies the repository. Among other things, it verifies that:

- the manifest has the expected fields and safe repository-relative paths;
- every scenario, reader, and fixture exists and is tracked;
- each binary fixture is well formed and has the declared magic;
- every Rust reader opens the fixture and magic assigned to its family;
- fixture paths, magic values, and command ownership are not accidentally
  shared;
- implemented commands agree with the upstream command table and Rust registry;
- scenarios really send the commands they claim to cover;
- the Dockerfile pins its base image, snapshot, packages, build flags, entropy,
  and clock setup;
- files that enter the reference image have not drifted from the audited
  submodule commit.

Reader validation checks the `magic` and `include_bytes!` path from the same
`Fixture::new` declaration. A matching string in an unrelated test does not
count. Code inside the real `#[cfg(test)] mod tests { ... }` module is ignored,
while production declarations before or after that module are still checked.
If the small Rust scanner cannot understand a relevant declaration safely, the
audit fails instead of guessing.

Commands that use Docker (`build`, `verify`, `update`, and `diff`) first run the
static audit and then validate the resolved image itself.

## Safe fixture updates

Updating several fixtures is transactional:

1. Capture every selected family before touching committed files.
2. For every destination, back up the old file and prepare the new file beside
   it while remembering the original file mode.
3. After every replacement is prepared, atomically install them with
   `os.replace`.
4. Read every replacement back and verify its contents.
5. Remove backups and temporary files after the update is committed.

If capture, replacement, validation, or `Ctrl-C` fails before the commit point,
the command restores every file it already replaced. A newly created fixture is
removed. Original file modes are preserved as reported by the filesystem.

If rollback itself cannot restore a file, its backup is kept and its path is
printed so it can be recovered manually. Cleanup errors after a successful
commit never roll back the new fixtures.

`verify`, `diff`, and `audit` never write fixture files.

## Merge conflicts in fixtures

Do not merge the bytes of a `.bin` file. A fixture is derived output, so neither
side is authoritative on its own.

Resolve the scenario, manifest, and reference inputs first. Then take either
side of the binary conflict temporarily and regenerate the family:

```sh
python3 scripts/golden_responses/golden.py update <family>
python3 scripts/golden_responses/golden.py verify --all
```

Use `dump` or `diff` to understand the change, not to construct a merged binary.

## Relationship to the other tests

These fixtures cover deterministic command responses and TPM state. They sit
between unit tests and the full swtpm functional suite:

1. `cargo test` checks Rust implementation details and invariants.
2. Golden response tests compare Rust byte-for-byte with reference libtpms.
3. `make test-swtpm` checks the Rust library as a drop-in `libtpms.so`.

Cancellation, the swtpm control channel, and concurrency are intentionally left
to the swtpm suite because they depend on process interaction rather than a
deterministic command stream.
