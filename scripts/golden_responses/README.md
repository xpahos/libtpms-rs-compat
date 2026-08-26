# Golden response tests

Golden tests check that the Rust TPM behaves like the C implementation in the
vendored `libtpms` submodule.

For each test family, we run a scenario against a pinned reference build of
libtpms and save the results in a binary fixture. The Rust test then runs the
same commands and compares its results with that fixture.

```text
scenario -> reference libtpms -> fixture -> Rust test
```

The fixture is the oracle. If a Rust-only change breaks a golden test, fix the
Rust code. Do not regenerate the fixture to make the failure disappear.

## Commands you will normally use

| Command | What it does | Docker |
| --- | --- | --- |
| `make golden-audit` | Checks the manifest, scenarios, fixtures, readers, command coverage, and reference inputs. | No |
| `make test-golden` | Captures every scenario again and compares it with the committed fixtures. | Yes |
| `make update-golden FAMILY=<family>` | Regenerates one fixture after an intentional reference or scenario change. | Yes |
| `make update-golden-all` | Regenerates every fixture after the reference environment changes. | Yes |

`make check` includes `make golden-audit`. `make build` only builds the library;
use `make build PROFILE=release` for a release build.

To see the available families:

```sh
python3 scripts/golden_responses/golden.py list
```

## Pick the right workflow

### You changed only Rust code

Run the normal checks and the golden suite:

```sh
make check
make test-golden
```

Do not update fixtures. They still describe the reference behavior that the
Rust implementation is expected to match.

### You intentionally changed a scenario

First inspect what a fresh reference capture would change:

```sh
python3 scripts/golden_responses/golden.py diff <family>
```

If the change is expected, update that family and verify the complete set:

```sh
make update-golden FAMILY=<family>
make test-golden
```

Commit the scenario and its fixture together.

### You changed libtpms or the reference container

This can affect every fixture:

```sh
make update-golden-all
make check
make test-golden
```

Review every changed fixture. A new reference result may also require a Rust
implementation change.

### A golden test failed and you need to see why

Show the records that differ from a new capture:

```sh
python3 scripts/golden_responses/golden.py diff <family>
```

Print a fixture, or one record from it, as hexadecimal text:

```sh
python3 scripts/golden_responses/golden.py dump <family>
python3 scripts/golden_responses/golden.py dump <family> <record>
```

`diff` and `dump` never modify fixtures.

## What belongs to a family

The files have separate jobs:

- `manifest.toml` connects a family to its scenario, fixture, Rust reader,
  magic value, and TPM commands.
- `scenarios/*.scenario` describes what to run against reference libtpms.
- `runner.c` executes scenarios inside the reference container.
- `fixture_format.py` reads and writes the binary fixture format.
- `golden.py` audits, captures, compares, and updates fixtures.
- `Dockerfile` and `entropy_shim.c` define the reproducible reference
  environment.

Generated fixtures live in:

```text
src/library/tpm2/testdata/golden_responses/*.bin
```

Rust readers and tests live in:

```text
src/library/tpm2/golden_responses/*.rs
```

The `.bin` files are generated artifacts. Never edit them by hand.

## Reading a scenario

A scenario is a text file with one operation per line. The most common
operation sends a complete TPM command and saves the complete response under a
record name:

```text
send CREATE_RSA 80010000000c000001440000
```

Record names use upper-case ASCII letters, digits, and underscores. By
convention, permanent-state records begin with `PERMALL_` and volatile-state
records begin with `VOLATILE_`.

### Scenario operations

| Operation | Meaning |
| --- | --- |
| `profile <json>` | Erase NVRAM and manufacture a TPM with this profile. |
| `send NAME <hex>` | Send a command and save its response. |
| `raw <hex>` | Send a command without saving its response. |
| `permall NAME` | Save permanent TPM state as a fixture record. |
| `snapshot NAME` | Save permanent and volatile state as records and make the state restorable. |
| `checkpoint NAME` | Make the current state restorable without adding records. |
| `restore NAME` | Restore permanent and volatile state. |
| `restore-permanent NAME` | Restore only permanent state. |
| `reboot` | Reinitialize the TPM without erasing NVRAM. |
| `advance <ms>` | Advance the deterministic clock. |
| `locality <n>` | Change the platform locality. |
| `physical-presence <0\|1>` | Turn reported physical presence off or on. |
| `remember-session` | Remember the session created by the previous command. |
| `audited-getrandom NAME` | Run `TPM2_GetRandom` through the remembered session. |
| `exclusive-audit NAME` | Save the exclusive-audit handle from volatile state. |
| `fail-stores <0\|1>` | Turn simulated NVRAM write failures off or on. |
| `patch-failure-code <n>` | Change the saved failure-mode code and restore that state. |
| `version` | Save the libtpms version. |

`make golden-audit` validates the scenario language before Docker starts. It
rejects unknown operations, invalid arguments, duplicate record names, broken
restore references, and incorrect command coverage. Malformed TPM packets are
allowed because error handling is part of the compatibility surface.

## Keeping scenario sections independent

Stateful scenarios should take a `snapshot` or `checkpoint` after setup and
restore it before each independent section:

```text
checkpoint READY

restore READY
send FIRST_CASE ...

restore READY
send SECOND_CASE ...
```

This prevents one case from changing handles, random state, clocks, or
persistent state used by another case. It is especially important for commands
that create objects, open sessions, reboot the TPM, or destroy state.

## When one command needs bytes returned by another

Some requests need opaque output from an earlier command: a private object
blob, a saved context, ciphertext, or a session nonce. Scenario files cannot
refer to a slice of an earlier response, so these cases use a two-pass update:

1. Add and capture the command that produces the value.
2. Inspect its record with `golden.py dump`.
3. Put the required bytes into the consuming command.
4. Capture the family again.
5. Run `make test-golden`.

Keep the producing and consuming sections reproducible with `restore`. In the
Rust test, read the value from the producer record instead of duplicating the
bytes in source code.

The `object-lifecycle`, `credential-activation`, `policy-sessions`, `hmac`, and
`encrypt-decrypt` families contain examples of this pattern.

## Why two fresh captures match

A normal TPM reads host entropy and several clocks. That would make keys,
sessions, and state blobs change on every run. The reference container removes
those sources of variation:

- `entropy_shim.c` supplies deterministic OpenSSL randomness and monotonic
  clocks;
- libfaketime freezes wall-clock time;
- the Debian snapshot, packages, compiler flags, libtpms commit, platform,
  entropy seed, and clock settings are pinned.

The deterministic random stream exists only in the capture container. It is not
used by the Rust library in production and must not be treated as secure.

Before a fixture is captured, `golden.py` checks the image and its pinned
inputs. It also runs a reproducibility probe in two fresh containers and
requires identical output.

The image is built from tracked capture files and the committed libtpms
submodule revision. It is cached by content and platform, so build artifacts and
untracked files cannot silently change the reference.

The reference platform is declared in `manifest.toml`. It is part of the
compatibility definition, so a host on another architecture may run the image
through emulation.

## What the audit checks

`make golden-audit` keeps the repository metadata and the actual code aligned.
Among other things, it checks that:

- manifest paths stay inside the repository;
- every declared scenario, fixture, and reader exists and is tracked;
- every fixture has the expected structure and magic value;
- readers open the fixture and magic value declared for their family;
- fixture paths, magic values, and command ownership do not overlap;
- the upstream command table, Rust registry, and manifest agree;
- scenarios exercise the commands they claim to cover;
- inputs used to build the reference image have not drifted.

Commands that capture fixtures run this audit before they start Docker and then
validate the resolved image as well.

The command status in `manifest.toml` has a precise meaning:

- `implemented` means the command exists in the pinned reference and in Rust;
- `todo` means the reference exposes the command but Rust does not implement it
  yet;
- `waived` means the pinned reference profile explicitly compiles the command
  out with `CC_NO`.

`waived` is not another spelling of `todo`. A waived command must name its own
`CC_* CC_NO` setting and must not be registered by Rust.

The `disabled-commands` family records the dispatch and capability behavior of
the profile-disabled commands. `TPM2_ACT_SetTimeout` is also profile-disabled,
but its records live in `platform-state` because they are next to the other ACT
and platform capability cases.

## Updating fixtures safely

An update first captures and validates every selected family in temporary
files. Only then does it replace committed fixtures. Replacements are atomic
and are validated again after installation.

If capture, validation, replacement, or `Ctrl-C` fails, the tool restores any
fixture it already replaced. If a backup cannot be restored, its path is
printed so it can be recovered manually.

`audit`, `verify`, and `diff` are read-only. Only `update` replaces fixtures.
Updating all families additionally requires `--confirm-reference-update`,
which is supplied by `make update-golden-all`.

## Cases that are intentionally not byte-for-byte

Most records are compared as raw bytes, but a few reference results contain
legitimate randomness or state that cannot be shared between implementations.
The corresponding Rust readers make the narrower comparison that preserves the
real contract:

- randomized ECDSA and RSA-PSS results compare the signed body and verify the
  returned signature instead of requiring identical signature bytes;
- some rebooted permanent-state records compare meaningful fields instead of a
  newly seeded random state blob;
- parameter-encryption cases derive the session key from the captured nonce and
  compare the decrypted value.

These exceptions belong in the family reader and its tests. Do not weaken the
fixture format or the common comparison code to accommodate one family.

For `TPM2_CertifyX509`, the fixture pins the certificate parts and TBS digest.
The randomized signatures are verified with the signing key, including
negative checks with corrupted signatures. DER rejection cases and lazy
self-test behavior are covered by the scenario and module tests rather than
repeated here record by record.

## Resolving fixture merge conflicts

Do not combine bytes from two conflicting `.bin` files. Resolve the scenario,
manifest, reader, and reference-input conflicts first. Then choose either
fixture side temporarily and regenerate the family from the resolved sources:

```sh
python3 scripts/golden_responses/golden.py update <family>
python3 scripts/golden_responses/golden.py verify --all
```

Use `dump` and `diff` to inspect the result. Never assemble a fixture manually.

## Direct `golden.py` interface

The Make targets cover normal work. The underlying commands are available when
you need a single family or more detail:

| Command | Meaning |
| --- | --- |
| `audit` | Validate repository metadata and fixture structure without Docker. |
| `build` | Audit and build or reuse the reference image. |
| `verify <family>` | Capture and compare one family. |
| `verify --all` | Capture and compare every family. |
| `update <family>` | Capture and safely replace one fixture. |
| `update --all --confirm-reference-update` | Capture and safely replace every fixture. |
| `diff <family>` | Show record-level differences from a fresh capture. |
| `dump <family> [record]` | Print fixture records as hexadecimal text. |
| `list` | List families, record counts, and covered commands. |

Run these as:

```sh
python3 scripts/golden_responses/golden.py <command>
```

## How golden tests fit with the other tests

The repository has three complementary layers:

1. `cargo test` checks Rust logic and state transitions.
2. Golden tests compare deterministic command behavior with reference libtpms.
3. `make test-swtpm` and `make test-swtpm-docker` exercise the Rust library as
   `libtpms.so` in a full swtpm workflow.

Process-level behavior such as control channels, cancellation, and concurrency
belongs in the swtpm suite. Command bytes and serializable TPM state belong in
the golden suite.
