# Golden response tests

Golden tests check that the Rust TPM behaves like the C implementation in the
vendored `libtpms` submodule.

For each test family, we run a scenario against a pinned reference build of
libtpms and save the results in a binary fixture. The Rust test then runs the
same commands and compares its results with that fixture.

The reference build is the `libtpms` submodule revision with the patch series
in `patches/` applied (see [The reference build](#the-reference-build)).

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

This includes adding, removing or editing a file in `patches/`. It can affect
every fixture:

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
- `patches/*.patch` are the upstream libtpms fixes applied to the submodule
  before the reference is built.

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
| `case <name>` ... `end-case` | Run the enclosed lifecycle steps in a fresh process (see below). |

A `checkpoint` may move an earlier checkpoint but must not reuse the name of a
recorded `snapshot`: the fixture keeps the snapshot's records, so a case that
read the checkpoint instead would replay different bytes than it captured.
The audit and the runner both reject such a checkpoint. A `snapshot` may take
over a checkpoint's name, because its records then match what the runner holds.

`make golden-audit` validates the scenario language before Docker starts. It
rejects unknown operations, invalid arguments, duplicate record names, broken
restore references, checkpoints over recorded snapshots, and incorrect command
coverage. Malformed TPM packets are allowed because error handling is part of
the compatibility surface.

## Lifecycle cases

Everything above runs in one process against one TPM that the runner has
already initialized. The library lifecycle itself (`TPMLIB_MainInit`, state
staging, the host callbacks, `TPMLIB_Terminate`) needs more: libtpms keeps the
TPM, the staged blobs, the callbacks and the failure diagnostics in process
globals, so every lifecycle case must start from a fresh process.

A `case <name>` block does exactly that. The runner re-executes itself for
the block, hands it the snapshots recorded so far (never a checkpoint),
selects TPM 2.0 and registers its callbacks, and runs the block without
initializing the TPM first. The parent skips the block and continues where it left off. A failing
case fails the capture. Case names are lower-case snake_case; they name the
Rust test that replays the case.

```text
snapshot BUSY
case partially_restored_volatile_state_keeps_unmarshalled_fields
nvram-put permall PERMALL_BUSY
nvram-put volatilestate VOLATILE_BUSY@drop=21
main-init LC_PARTIAL_LATE_INIT
get-state LC_PARTIAL_LATE_VOLATILE volatile
io-init 42
main-init LC_PARTIAL_LATE_UNFAIL
process LC_PARTIAL_LATE_GTR 80010000000a0000017c
end-case
```

Only these steps are valid inside a case, and none of them outside one:

| Step | Record |
| --- | --- |
| `main-init NAME` | `TPMLIB_MainInit` result. |
| `terminate` | None. |
| `set-state NAME permanent\|volatile BLOB` | `TPMLIB_SetState` result. |
| `get-state NAME permanent\|volatile` | Result, a buffer-present byte, and the state. |
| `volatile-all-store NAME` | Result, a buffer-present byte, and the state. |
| `set-profile NAME <json>` | `TPMLIB_SetProfile` result. |
| `process NAME <hex>` | `TPMLIB_Process` result followed by the response. |
| `was-manufactured NAME` | `TPMLIB_WasManufactured` as one byte. |
| `established NAME` | `TPM_IO_TpmEstablished_Get` result and flag. |
| `established-reset NAME` | `TPM_IO_TpmEstablished_Reset` result. |
| `hash-start NAME`, `hash-data NAME <hex>`, `hash-end NAME` | The `TPM_IO_Hash_*` result. |
| `nvram-put permall\|volatilestate BLOB` | None; stores the blob behind `tpm_nvram_loaddata`. |
| `load-fails permall\|volatilestate <code>` | None; `tpm_nvram_loaddata` answers the code (0 restores it). |
| `io-init <code>`, `nvram-init <code>` | None; `tpm_io_init` or `tpm_nvram_init` answers the code. |
| `callbacks NAME` | The callbacks since the last `callbacks` step: a 32-bit count, then one line each. |

Results are 32-bit big-endian values. A `BLOB` is a `PERMALL_<snapshot>` or
`VOLATILE_<snapshot>` record from an earlier `snapshot`, followed by any
number of modifiers applied from left to right: `@head=N` (keep N bytes),
`@drop=N` (remove the last N), `@flip=N` (invert byte N), `@flip-end=N`
(invert byte N counted from the end, 1 being the last), `@set=N:HEX` (write
the lower-case hex bytes at offset N) and `@sha1` (recompute a volatile
blob's SHA-1 trailer over the bytes before it). For example,
`VOLATILE_S@set=4183:0003@sha1@drop=21` edits a field, reseals the blob and
then cuts it. Callback lines name each call and its answer; loaded and stored
blobs appear with their length and `content=` the first blob of the case with
the same bytes, or `new`. `tpm_io_getphysicalpresence` is not logged: the Rust
port samples physical presence for every command it executes, libtpms only
when a command needs it.

A cut or flipped volatile blob leaves libtpms holding every field it wrote
before the defect, with one exception: a defect inside an `OBJECT` or
`HASH_OBJECT` body clears the whole object slot, occupied flag included. The
outer `ANY_OBJECT` header and its trailing block are outside that cleanup, so
a defect there leaves the slot as it was. Export such a state only when
libtpms can marshal it: a cut that leaves a union selector unset, for example
before a session's symmetric algorithm, makes libtpms assert outside a
command. Observe those states through `GetCapability`, `FlushContext` and an
export after the flush instead.

Export permanent state before a case's first command or after its
`TPM2_Shutdown`. In between, libtpms writes the orderly data, DRBG state
included, to NV whenever the clock crosses an update interval, and a restored
TPM's clock has moved by the host time since the capture.

`cargo test --test abi_lifecycle` replays every case against the library
under test through its exported C ABI: it `dlopen`s the library in a child
process per case, performs the same steps, and compares every record with the
fixture. Blobs a running TPM exports embed host time. A volatile export must
first carry a valid SHA-1 trailer over its own payload, in the reference record
and in the library's output alike; the comparison then covers every byte
except `g_time`, `go.clock`, `go.time`, the timer and host-clock tail fields,
`backthen`, and the already checked trailer. Permanent state is compared
except its NV copies of `go.clock` and `go.time`. Two environment variables
change what the test loads and keeps:

| Variable | Effect |
| --- | --- |
| `LIBTPMS_ABI_LIBRARY=/path/libtpms.so` | Load this library instead of the cdylib cargo built, for example a C libtpms. |
| `LIBTPMS_ABI_TRANSCRIPT_DIR=/dir` | Write one transcript per case: every ABI call with its native result and sizes, and every callback. |

A C libtpms built from the `libtpms` submodule passes the same test, which
keeps the replay honest about what it compares.

Any family may hold cases. `tests/abi_lifecycle/main.rs` lists the cases of
each such family and fails when a scenario holds cases it does not list. The
`policy-sessions` family uses them to replay NV policy authorization through
the ABI from its `NV_GATE_READY` snapshot. `process` responses are compared byte
for byte, so keep responses that depend on host time, such as an attestation
clock or dictionary-attack recovery, out of cases.

## The reference build

The capture image copies the committed `libtpms` submodule revision and applies
every `patches/*.patch` file to it in name order before it runs `autogen.sh`.
The patches use `git format-patch` output, so the first line of each file is
the upstream commit it was exported from. `make golden-audit` prints those
commits next to the submodule revision:

```text
reference:         libtpms v0.10.2 @ 03ff2481e133540be3b3ffe3daa1483d2a73d967 (platform linux/arm64)
reference patches: 4 upstream commit(s) 43c97ddf1765 043ebbc16d47 c5449222056d ab9803822ab8
```

The current series backports four `NVMarshal.c` fixes that were submitted
upstream on top of libtpms master (`a5fc3ae7`); each applies to v0.10.2
without fuzz:

| Patch | Upstream commit | Effect on the reference |
| --- | --- | --- |
| `0001` | `43c97ddf` | Loading permanent state keeps the saved `nullSeedCompatLevel`, so a `TPM_RH_NULL` RSA primary is the same after `TPM2_Startup(TPM_SU_STATE)`. |
| `0002` | `043ebbc1` | An `ANY_HASH_STATE` header error is returned instead of being replaced by the result of the hash payload. |
| `0003` | `c5449222` | A failed `OBJECT` or `HASH_OBJECT` body clears the whole object slot. |
| `0004` | `ab980382` | An orderly RAM entry whose size is below the header or past the array is written as the zero-size terminator. |

The audit rejects an untracked file in `patches/` (it would silently stay out
of the build), a patch that does not start with its upstream commit, and a
Dockerfile that does not apply the directory. The submodule itself must stay
clean: patches are applied only inside the image.

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
- the Debian snapshot, packages, compiler flags, libtpms commit, reference
  patches, platform, entropy seed, and clock settings are pinned.

The deterministic random stream exists only in the capture container. It is not
used by the Rust library in production and must not be treated as secure.

Before a fixture is captured, `golden.py` checks the image and its pinned
inputs. It also runs a reproducibility probe in two fresh containers and
requires identical output.

The image is built from tracked capture files, the committed libtpms
submodule revision and the tracked patch series. It is cached by content and
platform, so build artifacts and untracked files cannot silently change the
reference.

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
- every reference patch is tracked, names its upstream commit, and is applied
  by the Dockerfile;
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

1. `cargo test` checks Rust logic and state transitions, and replays the
   lifecycle cases through the exported C ABI.
2. Golden tests compare deterministic command behavior with reference libtpms.
3. `make test-swtpm` and `make test-swtpm-docker` exercise the Rust library as
   `libtpms.so` in a full swtpm workflow.

Process-level behavior such as control channels, cancellation, and concurrency
belongs in the swtpm suite. Command bytes and serializable TPM state belong in
the golden suite.
