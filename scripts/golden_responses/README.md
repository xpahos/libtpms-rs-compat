# Golden response tests

Golden tests answer a simple question: does the Rust TPM return the same bytes
as the reference C implementation in `libtpms/`?

Each test family has a scenario and a binary fixture. The scenario is first run
against libtpms in a deterministic Docker container. Its responses and selected
state blobs are saved in the fixture. Rust tests then replay the same commands
and compare their output with those saved bytes.

```text
scenario -> reference libtpms -> .bin fixture -> Rust test
```

The `.bin` files are generated. Do not edit them by hand and do not try to
resolve binary merge conflicts inside them.

## Everyday commands

Check that the manifest, scenarios, fixtures, and Rust readers agree:

```sh
make golden-audit
```

This is a fast, read-only check and does not need Docker. `make build` and
`make build-release` run it automatically.

Re-run every scenario against libtpms and compare the fresh captures with the
committed fixtures:

```sh
make test-golden
```

This needs Docker but does not change any fixture.

Regenerate one family after intentionally changing its scenario:

```sh
make update-golden FAMILY=create-primary
```

Regenerate every family after intentionally changing libtpms or the reference
container:

```sh
make update-golden-all
```

Updating everything is deliberately harder to do by accident. Use it only when
the reference itself has changed, and review every resulting fixture diff.

## Which workflow should I use?

### I changed only Rust code

```sh
make golden-audit
cargo test
make test-golden
```

If a golden test now fails, fix the Rust implementation. The fixture still
describes the expected answer, so regenerating it would only hide the bug.

### I changed a scenario

See which records the change affects, regenerate that family, and verify the
whole set:

```sh
python3 scripts/golden_responses/golden.py diff <family>
make update-golden FAMILY=<family>
make test-golden
```

Commit the scenario and its updated fixture together.

### I changed libtpms or the capture environment

```sh
make update-golden-all
make ci
```

Review every changed family. A new reference result may require corresponding
changes in the Rust implementation.

### I need to understand a mismatch

List the records that differ from a fresh reference capture:

```sh
python3 scripts/golden_responses/golden.py diff create-primary
```

Print a whole fixture or one record as hexadecimal text:

```sh
python3 scripts/golden_responses/golden.py dump create-primary
python3 scripts/golden_responses/golden.py dump create-primary RECORD_NAME
```

## Files and responsibilities

- `manifest.toml` lists the families and connects each scenario to its fixture,
  Rust reader, magic value, and covered TPM commands.
- `scenarios/*.scenario` contains the commands sent to reference libtpms.
- `runner.c` executes those scenarios.
- `fixture_format.py` reads and writes the binary fixture format.
- `Dockerfile` builds the pinned reference environment.
- `entropy_shim.c` provides deterministic entropy and clocks during capture.
- `golden.py` audits, captures, compares, and updates fixtures.

Generated fixtures are stored in:

```text
src/library/tpm2/testdata/golden_responses/*.bin
```

Their Rust readers are stored in:

```text
src/library/tpm2/golden_responses/*.rs
```

Each family has one scenario, one fixture, and one Rust reader. There is no
second fixture generator or hidden capture path.

## Scenario files

A scenario is a text file containing one operation per line. Operations that
save data assign it a record name. A fixture is the sorted collection of those
named records.

The most common operation sends a TPM packet and saves the complete response:

```text
send RECORD_NAME <hexadecimal TPM command>
```

Available operations are:

| Operation | Meaning |
| --- | --- |
| `profile <json>` | Erase NVRAM and manufacture a TPM with this profile. |
| `send NAME <hex>` | Send a TPM command and save its response. |
| `raw <hex>` | Send a TPM command without saving its response. |
| `permall NAME` | Save permanent TPM state. |
| `snapshot NAME` | Save permanent and volatile state as records and make them restorable. |
| `checkpoint NAME` | Remember permanent and volatile state without adding fixture records. |
| `restore NAME` | Restore both permanent and volatile state. |
| `restore-permanent NAME` | Restore permanent state only. |
| `reboot` | Reinitialize the TPM without erasing NVRAM. |
| `advance <ms>` | Advance the deterministic TPM clock. |
| `locality <n>` | Change the locality returned by the platform callback. |
| `physical-presence <0\|1>` | Change the physical presence reported by the platform callback. |
| `remember-session` | Remember the session created by the preceding command. |
| `audited-getrandom NAME` | Run `TPM2_GetRandom` through the remembered session. |
| `exclusive-audit NAME` | Save the exclusive-audit handle from volatile state. |
| `fail-stores <0\|1>` | Enable or disable simulated NVRAM write failures. |
| `patch-failure-code <n>` | Change the saved failure-mode code and restore that state. |
| `version` | Save the libtpms version. |

Record names use upper-case ASCII letters, digits, and underscores. By
convention, `PERMALL_*` records contain permanent state and `VOLATILE_*` records
contain volatile state. Other records normally contain TPM responses or small
values produced by the runner.

`make golden-audit` validates scenario syntax before Docker starts. It catches
unknown operations, bad arguments, duplicate record names, invalid restore
usage, and missing command coverage. Deliberately malformed TPM packets are
allowed because error handling also needs reference coverage.

## Reusing output from an earlier command

Some TPM commands consume opaque bytes produced by another command. Examples
include loading a private blob returned by `TPM2_Create`, loading a saved
context, decrypting ciphertext, and using a session nonce.

Scenario files cannot refer to a slice of an earlier response directly. The
usual workflow is therefore:

1. Add the producing command as a named `send` record.
2. Regenerate the family.
3. Use `golden.py dump` to inspect the produced bytes.
4. Paste the required bytes into the consuming command.
5. Regenerate and verify the family again.

Keep sections that consume captured bytes independent. Start each section from
a known `snapshot` or `checkpoint` with `restore`, and make the Rust test read
the producing fixture record instead of copying the same bytes into Rust code.

The `object-lifecycle` and `rsa-encryption` families are useful examples.

## Why the captures are reproducible

A normal TPM manufacture reads system entropy and clocks, so two fresh
containers would normally produce different keys and state blobs. The golden
container removes those sources of variation:

- `entropy_shim.c` replaces OpenSSL randomness with a deterministic stream;
- monotonic and CPU clocks advance only when a scenario asks them to;
- libfaketime freezes wall-clock time;
- the Debian snapshot, packages, compiler flags, libtpms commit, target
  platform, entropy seed, and clock settings are pinned.

The deterministic random stream exists only inside the fixture capture image.
It is not secure and is never used by the Rust library in production.

Before capturing anything, `golden.py` validates the image and its pins. It
also runs a probe in two fresh containers and requires both results to match.

## Reference image caching

`golden.py` builds a small Docker context from the tracked files under
`scripts/golden_responses/` and `git archive HEAD` from the `libtpms` submodule.
Build output, untracked files, and submodule `.git` data cannot enter the image.

The context and target platform are hashed. An existing image is reused only
when its tag, identity label, and platform match that hash.

`manifest.toml` is intentionally not part of the image hash: it describes how
the already-built runner is used, but does not change the runner itself. The
manifest is checked separately by `golden-audit`.

Only submodules included in the image must be clean. At present that means
`libtpms`; `swtpm` belongs to the separate integration-test workflow.

## What `golden-audit` protects

The audit is read-only and does not use Docker. It checks that:

- all manifest paths stay inside the repository;
- every declared scenario, fixture, and Rust reader exists and is tracked;
- fixtures have a valid structure and the declared magic value;
- each Rust reader opens the expected fixture with the expected magic;
- fixture paths, magic values, and command ownership are unique;
- implemented commands agree with the upstream table and Rust registry;
- scenarios really send the commands they claim to cover;
- inputs used to build the reference image have not drifted.

Commands that do use Docker (`build`, `verify`, `update`, and `diff`) run the
audit first and then validate the resolved image.

## Safe fixture updates

An update captures and validates every selected family before replacing any
fixture. Replacements are installed atomically and checked again after they are
written.

If capture, replacement, validation, or `Ctrl-C` fails, the tool restores every
fixture it has already replaced and removes newly created fixtures. If a backup
cannot be restored, the tool preserves it and prints its path for manual
recovery.

`audit`, `verify`, and `diff` never change fixture files.

## Resolving merge conflicts

Never combine the bytes from two conflicting `.bin` files. Resolve the scenario,
manifest, and reference-input conflicts first. Then choose either binary side
temporarily and regenerate the fixture from the resolved sources:

```sh
python3 scripts/golden_responses/golden.py update <family>
python3 scripts/golden_responses/golden.py verify --all
```

Use `dump` and `diff` to inspect fixtures, not to assemble them manually.

## Notes about the attestation family

The `attestation` family covers `TPM2_Certify`, `TPM2_CertifyCreation`,
`TPM2_Quote`, `TPM2_GetTime`, `TPM2_GetSessionAuditDigest`,
`TPM2_GetCommandAuditDigest`, and `TPM2_SetCommandCodeAuditStatus`.

Its scenario is split into independent sections. Each section starts with:

```text
restore READY
```

`READY` was captured immediately after `TPM2_Startup(TPM_SU_CLEAR)`. Restoring
both permanent and volatile state also restores the reference DRBG, so each
section creates the same keys and sessions.

RSASSA, HMAC, and null signatures are deterministic and are compared byte for
byte. Three records use randomized signatures:

- `CERTIFY_ECC` and `CERTIFY_ECC_EXPLICIT` use ECDSA;
- `CERTIFY_KEY_WITH_EXPLICIT_PSS` uses RSA-PSS.

For those records, the Rust test compares the attestation bytes and verifies
the signature with the public key instead of comparing the raw signature bytes.
The reference consumes extra randomness in lazy RSA and ECC known-answer tests,
while the Rust implementation currently models only the lazy OAEP test.

The command-audit section covers enabling and disabling auditing, audited and
unaudited commands, reading and resetting the digest, changing its hash
algorithm, duplicate list entries, and entries that cause no state change.
Permanent-state records pin the bitmap and audit counter after mutations.

One deliberate compatibility case enables auditing for
`TPM2_ActivateCredential`. The vendored reference implements that command and
the active profile enables it, although the Rust dispatcher does not implement
it yet. The fixture therefore preserves the upstream audit bit and includes it
in the command-list digest.

## Notes about the policy-sessions family

The `policy-sessions` family covers `TPM2_StartAuthSession` and every policy
command. Its scenario is a sequence of independent sections; each one starts
from `restore READY`, `restore POLICY_FRESH`, or `restore TRIAL_FRESH` so one
section cannot influence the next.

Four sections consume bytes produced earlier in the same scenario and therefore
need the two-pass workflow described above:

- `PTKT_*` replay the `timeout` and `TPMT_TK_AUTH` returned by
  `PSEC_TICKET_FOR_REUSE`;
- `PSIGN_ACCEPTED` replays the RSASSA signature returned by `SIGN_AHASH`;
- `VERIFY_APPROVED` replays the signature returned by `SIGN_APPROVED`;
- `PAUTH_ACCEPTED` replays the key name from `SIGNING_KEY_PUBLIC` and the
  `TPMT_TK_VERIFIED` from `VERIFY_APPROVED`.

Regenerate the family, read the producing record with `golden.py dump`, paste the
bytes into the consuming command, and regenerate again. The Rust tests slice the
same bytes out of the producing fixture record instead of repeating them.

The `FLOW_*` sections show a policy actually authorizing a command. Each one
defines an NV index whose `authPolicy` is a policy digest computed off-line,
builds that policy in a real session, and then reads the index through it. They
pin the enforcement of `TPMA_NV_WRITTEN`, command locality, and physical
presence at authorization time, and each section records the built policy digest
so a failure cannot be mistaken for a digest mismatch.

`FLOW_NV_READ_LOCALITY_TWO` uses the scenario `locality` operation. The locality
is restored to 0 immediately afterwards so later sections are unaffected.

The `NVUSS_*` and `HCA_*` sections pin how the reference builds a response
authorization when the command changes the entity that authorized it. Their
command HMACs are computed off line, so they also use the two-pass workflow: the
session nonce comes from `NVUSS_SESSION` and `HCA_SESSION`.

`NVUSS_*` deletes the very NV index that authorized `TPM2_NV_UndefineSpaceSpecial`
through `TPM2_PolicyAuthValue`; the reference answers with a response HMAC keyed
by the session key alone, because the association to the deleted index is
dropped. The `NVUSS_AFTER_DELETE` snapshot is taken immediately after that
command so the Rust tests can compare the recorded session-process association
with the vendored one. `HCA_CHANGED` shows the opposite case: `TPM2_HierarchyChangeAuth` keys
its response HMAC with the authorization value it just installed, not the one
the command was authorized with.

`TPM2_PolicyCapability` mixes only `operandB`, `offset`, `operation`,
`capability`, and `property` into the policy digest, never the capability data
itself. Its records therefore differ from the reference only in whether the
comparison succeeds.

## Notes about NV PIN indexes

The `nv-commands` family ends with two sections that pin how the session layer
maintains the counter of a PIN index. Both start from `restore-permanent
NV_PIN_BASE` followed by `TPM2_Startup`, which is the state the Rust tests
rebuild from the `PERMALL_BASE` record.

`PIN_PASS_*` shows that every authorized use of the index authorization value
increments `pinCount` before the command runs, and that reaching `pinLimit`
makes the authorization value unavailable. `PIN_FAIL_*` shows the mirror image:
a failed authorization increments the counter and a successful one clears it.
Reads authorized by the owner never touch the counter.

## Notes about the stateless cryptographic families

The `encrypt-decrypt`, `hmac`, and `test-parms` families cover
`TPM2_EncryptDecrypt`, `TPM2_EncryptDecrypt2`, `TPM2_HMAC`, and
`TPM2_TestParms`. Their keys are created with `sensitiveDataOrigin` CLEAR and an
explicit `inSensitive.data`, so the scenario knows the key material and can
carry the matching ciphertext for the decrypting half of each round trip
without a second capture pass.

Command code `0x0155` reaches `TPM2_MAC` and `0x015b` reaches `TPM2_MAC_Start`,
because the reference enables `ALG_CMAC`. Both MAC paths are implemented: a
keyed-hash key answers an HMAC and a symmetric key whose mode is `TPM_ALG_CMAC`
answers a CMAC. The `hmac` records show the MAC scheme selection order, its
`TPM_RC_SYMMETRIC` unmarshaling error, and successful one-shot CMACs for AES,
TDES, and Camellia. The `sequence-commands` `Y_*` records show the same key
driven incrementally through `TPM2_MAC_Start`, `TPM2_SequenceUpdate`,
`TPM2_SequenceComplete`, `TPM2_ContextSave`, and `TPM2_FlushContext`.

The reference stores a CMAC sequence as an `hmacSeq` object whose `HASH_STATE`
carries `HASH_STATE_SMAC` with a zero `hashAlg`, so `ANY_HASH_STATE_Marshal()`
writes no state bytes and the `hmacKey` stays empty. `VOLATILE_Y_AFTER_START`
and `VOLATILE_Y_AFTER_UPDATE` pin that image; the working CMAC value lives
outside the serialized object in both implementations.

A CMAC sequence therefore cannot be resumed. `TPM2_ContextSave` still returns a
context blob for one, and the reference still loads that blob: `Z_CMAC_CONTEXT_SAVE`
succeeds, `Z_CMAC_CONTEXT_LOAD` succeeds, and `Z_TRANSIENT_AFTER_LOAD` shows the
new handle. The loaded object has no CMAC value, and using it makes the reference
call a null `smacMethods` pointer, so the scenario stops at the load. The Rust
implementation returns the same bytes for all three commands and then answers
`TPM_RC_FAILURE` for a `TPM2_SequenceUpdate` or `TPM2_SequenceComplete` on the
restored handle instead of crashing.

`Z_HASH_*` and `Z_HMAC_*` cover the working case: a hash sequence and an HMAC
sequence both survive `ContextSave` -> `FlushContext` -> `ContextLoad` and
complete with the digest of the whole message.

Restoring volatile state that holds a live CMAC sequence is worse: the reference
takes SIGBUS inside `TPMLIB_SetState(VOLATILE)`, so no fixture can record it. The
Rust implementation refuses that blob while attaching it, which keeps the failure
at the same load boundary without producing an object that looks usable.

Only the hash states a sequence actually uses are validated when a saved object
is parsed. The reference leaves the unused entries of `state.hashState[]`
uninitialised, so real state files carry stale type and algorithm bytes there;
`swtpm/tests/data/tpm2state3b/tpm2-00.volatilestate` is one such file.

`CryptCmacEnd()` uses the `0x87` subkey constant for every block size, including
the 64-bit TDES block where SP800-38B specifies `0x1b`. The `G_MAC_TDES192_CMAC`
and `Y_CMAC_TDES_COMPLETE` records pin that deviation.

The reference container configures libtpms with
`--disable-use-openssl-functions`, so the symmetric modes come from the TPM's
own implementation. A partial final CFB block leaves the trailing `ivOut` bytes
zeroed; CTR, OFB, and CBC keep their full chaining state, and ECB answers an
empty `ivOut`.

The `encrypt-decrypt` `G_*` section and the `hmac` `F_*` and `I_*` sections use
an unbound, unsalted HMAC session for parameter encryption. Its session key is
empty, so the reference accepts an empty session HMAC and the parameter key is
`KDFa(SHA256, "", "CFB", nonceCaller, nonceTPM)`. Those sections consume the
`nonceTPM` returned by `G_SESSION`, `F_SESSION`, and `I_SESSION` and therefore
need the two-pass workflow described above. Each of them restores `G_READY`,
`F_READY`, or `I_READY` so every command sees the same `nonceTPM`.

## Notes about the platform-state family

The `platform-state` family covers `TPM2_ClockSet`, `TPM2_ClockRateAdjust`,
`TPM2_ReadClock`, `TPM2_PP_Commands`, `TPM2_SetAlgorithmSet`,
`TPM2_PCR_SetAuthValue`, and `TPM2_ACT_SetTimeout`. Its scenario is a sequence
of independent sections; each one starts from `restore READY`, the snapshot
taken right after `TPM2_Startup(TPM_SU_CLEAR)`.

Three findings drive how the family is built.

`TPM2_ACT_SetTimeout` is not implemented by the reference. The pinned profile
sets `CC_ACT_SetTimeout` to `CC_NO`, so every request answers
`TPM_RC_COMMAND_CODE`, whatever the handle or the timeout. The `ACT_*` records
pin that, and the Rust dispatcher matches it by leaving the command
unregistered. `TPM_CAP_ACT` is implemented, though: it accepts any handle in
`TPM_RH_ACT_0..TPM_RH_ACT_F`, answers an empty list, and rejects anything else
with `TPM_RC_VALUE` for parameter two.

`TPM2_PCR_SetAuthValue` always fails. The vendored platform PCR table puts every
PCR in authorization group zero, so `PCRBelongsAuthGroup()` never matches and the
command answers a bare `TPM_RC_VALUE` before it can reach the orderly-state
check. The `PSAV_*` records cover every implemented PCR, both authorization
value extremes, and the unmarshaling errors that are reported first.

`TPM2_PP_Commands` requires asserted physical presence, because the vendored
attribute table gives it `PP_REQUIRED` and manufacturing installs that bit in
`ppList`. Capturing anything but `TPM_RC_PP` therefore needs the
`physical-presence` scenario operation. The `PPC_*` section turns presence on
and off around each step, so the same fixture holds the refusals, the accepted
mutations, and the follow-up `TPM2_ClearControl` and `TPM2_HierarchyControl`
commands that show the updated bitmap gating dispatch. Presence is returned to 0
at the end of the section, like the `locality` operation.

Clock records are compared byte for byte. The container's monotonic clock only
moves when the scenario says `advance`, and restoring volatile state also
restores the timer baseline, so a Rust test that restores the same snapshot and
repeats the same advances reads the same `TPMS_TIME_INFO`. The `RATE_*` records
use that to show the adjustment rate changing how fast the reported clock runs,
including saturation at the platform limit. The `CLK_*` section reboots without
an orderly shutdown to show `TPM2_ClockSet` making the clock safe again.

Two records in this family are not compared byte for byte by the Rust tests.
`CCATTR_0198` asks `TPM_CAP_COMMANDS` about the unimplemented ACT command; the
reference answers with `TPM2_ECC_Encrypt`, which the Rust dispatcher does not
implement yet, so the test only checks that both skip `0x0198`. The
`PERMALL_*_RESTART` snapshots are compared field by field instead of byte for
byte, because a reboot re-seeds the DRBG from host entropy and the Rust test
entropy is not the container's.

## Notes about destructive scenarios

Commands such as `TPM2_Clear`, `TPM2_ChangeEPS`, and `TPM2_ChangePPS` destroy or
replace state. Their scenario sections start from `restore READY` so one section
cannot affect the next. Restoring volatile state matters because it also
restores the reference DRBG.

When new hierarchy seeds make raw state unsuitable for direct comparison, the
scenario checks observable effects through normal TPM commands: capabilities,
PCR values, public objects, NV indexes, and shutdown/startup behavior.

The `hierarchy-management` family also preserves an upstream state-format
quirk. Legacy level-1 persistent objects and newer `ANY_OBJECT` entries place
hierarchy attributes differently, but libtpms hierarchy flushing still reads
the old offset. As a result, some persistent objects survive hierarchy-changing
commands in newer formats. The `LEGACY_*`, `PPS_*`, and `CLR_*` records preserve
that behavior intentionally.

## Direct `golden.py` commands

The Make targets above call `golden.py`, but its complete interface is also
available directly:

| Command | Meaning |
| --- | --- |
| `audit` | Validate repository metadata and fixture structure without Docker. |
| `build` | Audit and build or reuse the validated reference image. |
| `verify <family>` | Capture and compare one family. |
| `verify --all` | Capture and compare every family. |
| `update <family>` | Safely replace one fixture. |
| `update --all --confirm-reference-update` | Safely replace every fixture. |
| `diff <family>` | Show records that differ from a fresh capture. |
| `dump <family> [record]` | Print fixture records as hexadecimal text. |
| `list` | List families, files, record counts, and covered TPM commands. |

## Where golden tests fit

The repository has three complementary test layers:

1. `cargo test` checks Rust logic and state transitions.
2. Golden tests compare deterministic command results with libtpms.
3. `make test-swtpm` runs the Rust library as `libtpms.so` in a full swtpm
   workflow.

Process-level behavior such as cancellation, control channels, and concurrency
belongs in the swtpm suite rather than in deterministic command scenarios.
