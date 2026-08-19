PYTHON          ?= python3
CARGO           ?= cargo
LIBTPMS_HEADER  := libtpms/include/libtpms/tpm_library.h

# ---------------------------------------------------------------------------
# Platform-specific values (centralized; do not scatter uname checks below)
# ---------------------------------------------------------------------------
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
DYLIB_NAME               := libtpms.dylib
LIBTPMS_RUNTIME_NAME     := libtpms.0.dylib
RUNTIME_LIBRARY_PATH_VAR := DYLD_LIBRARY_PATH
LINK_INSPECT             := otool -L
READELF_CMD              := true
# Rewrite the install name of the copied dylib so anything linked against it
# records (and resolves) the profile-specific prefix path, not Cargo's
# private deps/ path.  macOS SIP strips DYLD_* across protected binaries,
# so the absolute install name is what actually guarantees resolution.
LIB_ID_FIXUP              = install_name_tool -id "$(PREFIX_RUNTIME_LIB)" "$(PREFIX_RUNTIME_LIB)"
# CUSE is Linux-only; macOS FUSE ports lack cuse_lowlevel.h but still make
# configure's fuse pkg-config probe succeed, so disable it explicitly.
SWTPM_CONFIGURE_FLAGS    := --without-cuse
else ifeq ($(UNAME_S),Linux)
DYLIB_NAME               := libtpms.so
LIBTPMS_RUNTIME_NAME     := libtpms.so.0
RUNTIME_LIBRARY_PATH_VAR := LD_LIBRARY_PATH
LINK_INSPECT             := ldd
READELF_CMD              := readelf -d
LIB_ID_FIXUP              = true
SWTPM_CONFIGURE_FLAGS    :=
else
$(error unsupported operating system '$(UNAME_S)'; supported: Linux, Darwin)
endif
LIBTPMS_BUILD_NAME := $(DYLIB_NAME)

ABI_GENERATOR   := scripts/generate_libtpms_abi.py
ABI_OUTPUT      := src/generated/tpm_library_abi.rs
TIS_HEADER      := libtpms/include/libtpms/tpm_tis.h
TIS_ABI_OUTPUT  := src/generated/tpm_tis_abi.rs
FFI_TYPES       := src/ffi_types.rs

PA_FIXTURE_GENERATOR := scripts/generate_pa_compile_constants_fixture.py
NVMARSHAL_SOURCE     := libtpms/src/tpm2/NVMarshal.c

NV_LAYOUT_FIXTURE_GENERATOR := scripts/generate_nv_layout_fixture.py
TPM2_GLOBAL_HEADER          := libtpms/src/tpm2/Global.h

DRBG_FIXTURE_GENERATOR := scripts/generate_drbg_manufacture_fixture.py
CRYPTRAND_SOURCE       := libtpms/src/tpm2/crypto/openssl/CryptRand.c

VOLATILE_FIXTURE_GENERATOR := scripts/generate_volatile_state_fixture.py

HASH_FIXTURE_GENERATOR := scripts/generate_hash_ticket_fixture.py
TICKET_SOURCE          := libtpms/src/tpm2/Ticket.c

CANCEL_FIXTURE_GENERATOR := scripts/generate_cancel_checkpoints_fixture.py
ALGORITHM_TESTS_SOURCE   := libtpms/src/tpm2/AlgorithmTests.c

FAILURE_LOCATIONS_FIXTURE_GENERATOR := scripts/generate_failure_locations_fixture.py
EXEC_COMMAND_SOURCE                 := libtpms/src/tpm2/ExecCommand.c

# ---------------------------------------------------------------------------
# Cargo target directory / profile selection
# ---------------------------------------------------------------------------
CARGO_TARGET_DIR ?= $(CURDIR)/target
export CARGO_TARGET_DIR
PROFILE ?= debug

# Map the profile to the existing Cargo build target.
ifeq ($(PROFILE),debug)
CARGO_PROFILE_TARGET := build
else ifeq ($(PROFILE),release)
CARGO_PROFILE_TARGET := build-release
else
$(error unsupported PROFILE '$(PROFILE)'; supported profiles: debug, release)
endif

PROFILE_TARGET_DIR := $(CARGO_TARGET_DIR)/$(PROFILE)
SWTPM_TARGET_DIR   := $(PROFILE_TARGET_DIR)/swtpm
SWTPM_PREFIX       := $(SWTPM_TARGET_DIR)/prefix
SWTPM_BUILD_DIR    := $(SWTPM_TARGET_DIR)/build
SWTPM_SRC_DIR      := $(CURDIR)/swtpm

LIBTPMS_INCLUDE_DIR    := $(CURDIR)/libtpms/include/libtpms
LIBTPMS_PUBLIC_HEADERS := $(wildcard $(LIBTPMS_INCLUDE_DIR)/*.h)
# Version advertised via pkg-config; must satisfy swtpm's `libtpms >= 0.10`
# requirement and match the pinned libtpms submodule (v0.10.1).
LIBTPMS_PC_VERSION     := 0.10.1

CARGO_BUILT_LIB     := $(PROFILE_TARGET_DIR)/$(LIBTPMS_BUILD_NAME)
SWTPM_PKGCONFIG_DIR := $(SWTPM_PREFIX)/lib/pkgconfig
LIBTPMS_PC          := $(SWTPM_PKGCONFIG_DIR)/libtpms.pc
PREFIX_LIB          := $(SWTPM_PREFIX)/lib/$(LIBTPMS_BUILD_NAME)
PREFIX_RUNTIME_LIB  := $(SWTPM_PREFIX)/lib/$(LIBTPMS_RUNTIME_NAME)

SWTPM_HEADERS_STAMP   := $(SWTPM_TARGET_DIR)/.headers-installed
SWTPM_CONFIGURE_STAMP := $(SWTPM_TARGET_DIR)/.configured

JOBS ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)

.PHONY: all build build-release generate-abi check-generated-inputs check-generated-abi check-ffi-types check-pa-fixture check-nv-layout-fixture check-drbg-fixture check-volatile-fixture check-hash-fixture check-cancel-fixture check-failure-locations-fixture test-abi cargo-check check clean \
	prepare-swtpm build-swtpm test-swtpm clean-swtpm verify-swtpm-linkage

all: check

# Build the library (debug profile). Regenerates the ABI stubs first; the
# generator only touches the file when its content changes, so cargo does
# not rebuild needlessly.
build: generate-abi check-generated-inputs
	$(CARGO) build
	@echo "built: $(CARGO_TARGET_DIR)/debug/$(DYLIB_NAME)"

# Build the library with optimizations (release profile).
build-release: generate-abi check-generated-inputs
	$(CARGO) build --release
	@echo "built: $(CARGO_TARGET_DIR)/release/$(DYLIB_NAME)"

# Regenerate the Rust ABI stubs from the pinned libtpms public header.
# The generator only rewrites $(ABI_OUTPUT) when its content changes.
generate-abi:
	@test -f $(LIBTPMS_HEADER) || { \
		echo "error: $(LIBTPMS_HEADER) not found; run 'git submodule update --init libtpms'" >&2; \
		exit 1; \
	}
	$(PYTHON) $(ABI_GENERATOR) \
		--header $(LIBTPMS_HEADER) \
		--output $(ABI_OUTPUT)
	$(PYTHON) $(ABI_GENERATOR) \
		--header $(TIS_HEADER) \
		--output $(TIS_ABI_OUTPUT)

check-generated-inputs: check-pa-fixture check-nv-layout-fixture check-drbg-fixture check-volatile-fixture check-hash-fixture check-cancel-fixture

# Verify that the committed generated file is current: regenerate into a
# temporary directory and diff against $(ABI_OUTPUT).
check-generated-abi:
	@test -f $(LIBTPMS_HEADER) || { \
		echo "error: $(LIBTPMS_HEADER) not found; run 'git submodule update --init libtpms'" >&2; \
		exit 1; \
	}
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	$(PYTHON) $(ABI_GENERATOR) \
		--header $(LIBTPMS_HEADER) \
		--output "$$tmp/tpm_library_abi.rs" >/dev/null && \
	if ! diff -u $(ABI_OUTPUT) "$$tmp/tpm_library_abi.rs"; then \
		echo "error: $(ABI_OUTPUT) is stale; run 'make generate-abi' and commit the result" >&2; \
		exit 1; \
	fi && \
	$(PYTHON) $(ABI_GENERATOR) \
		--header $(TIS_HEADER) \
		--output "$$tmp/tpm_tis_abi.rs" >/dev/null && \
	if ! diff -u $(TIS_ABI_OUTPUT) "$$tmp/tpm_tis_abi.rs"; then \
		echo "error: $(TIS_ABI_OUTPUT) is stale; run 'make generate-abi' and commit the result" >&2; \
		exit 1; \
	fi && \
	echo "check-generated-abi: OK"

# Verify that the handwritten FFI type module and the header agree in both
# directions: every header type has a Rust counterpart, and every Rust type
# corresponds to a header type.
check-ffi-types:
	@test -f $(LIBTPMS_HEADER) || { \
		echo "error: $(LIBTPMS_HEADER) not found; run 'git submodule update --init libtpms'" >&2; \
		exit 1; \
	}
	$(PYTHON) $(ABI_GENERATOR) \
		--header $(LIBTPMS_HEADER) \
		--check-ffi-types $(FFI_TYPES)

# Verify that the checked-in PA_COMPILE_CONSTANTS fixture still matches
# what the vendored C implementation marshals: the generator recompiles
# the upstream pa_compile_constants[] table against the vendored profile
# headers and compares the result against the committed fixture.
check-pa-fixture:
	@test -f $(NVMARSHAL_SOURCE) || { \
		echo "error: $(NVMARSHAL_SOURCE) not found; run 'git submodule update --init libtpms'" >&2; \
		exit 1; \
	}
	$(PYTHON) $(PA_FIXTURE_GENERATOR) --check

# Verify that the checked-in reserved-NV layout fixture still matches
# what the vendored C headers describe: the generator recompiles a
# sizeof/offsetof oracle against the vendored profile headers and
# compares the result against the committed fixture.
check-nv-layout-fixture:
	@test -f $(TPM2_GLOBAL_HEADER) || { \
		echo "error: $(TPM2_GLOBAL_HEADER) not found; run 'git submodule update --init libtpms'" >&2; \
		exit 1; \
	}
	$(PYTHON) $(NV_LAYOUT_FIXTURE_GENERATOR) --check

# Verify that the checked-in Manufacture DRBG vector fixture still
# matches what the vendored C implementation computes: the generator
# extracts the CTR_DRBG primitives verbatim from the vendored
# CryptRand.c, replays the manufacture draw sequence against OpenSSL's
# AES, and compares the result against the committed fixture.
check-drbg-fixture:
	@test -f $(CRYPTRAND_SOURCE) || { \
		echo "error: $(CRYPTRAND_SOURCE) not found; run 'git submodule update --init libtpms'" >&2; \
		exit 1; \
	}
	$(PYTHON) $(DRBG_FIXTURE_GENERATOR) --check --quiet

# Verify that the checked-in VOLATILE_STATE fixtures still match what
# the vendored C implementation marshals: the generator compiles the
# real vendored VolatileState_Save/VolatileState_Marshal (NVMarshal.c,
# Marshal.c, Volatile.c) under a deterministic harness for the
# current-version fixtures, cross-validates a handwritten synthetic
# oracle against that output, re-emits the synthetic downgraded v1..v3
# layouts, and compares everything against the committed fixtures.
check-volatile-fixture:
	@test -f $(NVMARSHAL_SOURCE) || { \
		echo "error: $(NVMARSHAL_SOURCE) not found; run 'git submodule update --init libtpms'" >&2; \
		exit 1; \
	}
	$(PYTHON) $(VOLATILE_FIXTURE_GENERATOR) --check

# Verify that the checked-in TPM2_Hash / hash-check ticket fixture still
# matches what the vendored C implementation computes: the generator
# extracts TPM2_Hash, TicketIsSafe, TicketComputeHashCheck and the
# response marshalling chain verbatim from the vendored tree, runs them
# against OpenSSL's digests with fixed hierarchy proofs, and compares the
# result against the committed fixture.
check-hash-fixture:
	@test -f $(TICKET_SOURCE) || { \
		echo "error: $(TICKET_SOURCE) not found; run 'git submodule update --init libtpms'" >&2; \
		exit 1; \
	}
	$(PYTHON) $(HASH_FIXTURE_GENERATOR) --check --quiet

# Verify that the checked-in cancellation-checkpoint fixture still matches
# the vendored sources: the generator rescans the vendored TPM 2 tree for
# every place the platform cancel flag is polled, resolves the enclosing
# function, and compares the result against the committed fixture.
check-cancel-fixture:
	@test -f $(ALGORITHM_TESTS_SOURCE) || { \
		echo "error: $(ALGORITHM_TESTS_SOURCE) not found; run 'git submodule update --init libtpms'" >&2; \
		exit 1; \
	}
	$(PYTHON) $(CANCEL_FIXTURE_GENERATOR) --check

check-failure-locations-fixture:
	@test -f $(EXEC_COMMAND_SOURCE) || { \
		echo "error: $(EXEC_COMMAND_SOURCE) not found; run 'git submodule update --init libtpms'" >&2; \
		exit 1; \
	}
	$(PYTHON) $(FAILURE_LOCATIONS_FIXTURE_GENERATOR) --check

test-abi:
	$(PYTHON) -m unittest discover -s scripts/tests

cargo-check:
	$(CARGO) check

check: test-abi check-generated-abi check-ffi-types check-pa-fixture check-nv-layout-fixture check-drbg-fixture check-volatile-fixture check-hash-fixture check-cancel-fixture check-failure-locations-fixture cargo-check

clean:
	$(CARGO) clean
	rm -rf build

# ---------------------------------------------------------------------------
# swtpm integration: build and test upstream swtpm against the Cargo-built
# Rust libtpms replacement.
#
#   make test-swtpm                 # debug profile
#   make test-swtpm PROFILE=release # release profile
#
# Chain: <cargo build target> -> prepare-swtpm -> build-swtpm -> test-swtpm
# All artifacts live under $(CARGO_TARGET_DIR)/<profile>/swtpm/.
# ---------------------------------------------------------------------------

# The Cargo target above is the only thing that produces this file; this
# rule exists purely to fail with a clear message when it is missing.
$(CARGO_BUILT_LIB):
	@echo "error: Cargo-built library $(CARGO_BUILT_LIB) is missing; run 'make $(CARGO_PROFILE_TARGET)'" >&2
	@exit 1

# Install the Cargo-built shared library into the local prefix under its
# runtime name, plus the platform-appropriate development-name symlink.
$(PREFIX_RUNTIME_LIB): $(CARGO_BUILT_LIB)
	@mkdir -p $(SWTPM_PREFIX)/lib
	cp -f $(CARGO_BUILT_LIB) $(PREFIX_RUNTIME_LIB)
	$(LIB_ID_FIXUP)
	ln -sf $(LIBTPMS_RUNTIME_NAME) $(PREFIX_LIB)

# Install the public libtpms ABI headers from the pinned submodule.
$(SWTPM_HEADERS_STAMP): $(LIBTPMS_PUBLIC_HEADERS)
	@test -n "$(LIBTPMS_PUBLIC_HEADERS)" || { \
		echo "error: no libtpms headers found in $(LIBTPMS_INCLUDE_DIR); run 'git submodule update --init libtpms'" >&2; \
		exit 1; \
	}
	@mkdir -p $(SWTPM_PREFIX)/include/libtpms $(SWTPM_TARGET_DIR)
	cp -f $(LIBTPMS_PUBLIC_HEADERS) $(SWTPM_PREFIX)/include/libtpms/
	@touch $@

# pkg-config metadata pointing entirely at the profile-specific prefix.
# cryptolib matches swtpm's default so its configure-time consistency check
# passes.  Regenerated when this Makefile changes.
$(LIBTPMS_PC): Makefile
	@mkdir -p $(SWTPM_PKGCONFIG_DIR)
	@printf '%s\n' \
		'prefix=$(SWTPM_PREFIX)' \
		'exec_prefix=$${prefix}' \
		'libdir=$${exec_prefix}/lib' \
		'includedir=$${prefix}/include' \
		'cryptolib=openssl' \
		'' \
		'Name: libtpms' \
		'Description: Rust libtpms ABI-compatible implementation' \
		'Version: $(LIBTPMS_PC_VERSION)' \
		'Libs: -L$${libdir} -ltpms' \
		'Cflags: -I$${includedir}' \
		> $@
	@echo "generated $@"

# Generate swtpm's configure script when it is missing or its inputs changed.
# The wildcard keeps the prerequisite empty (instead of a hard make error)
# when the submodule is not checked out, so the recipe can report it.
$(SWTPM_SRC_DIR)/configure: $(wildcard $(SWTPM_SRC_DIR)/configure.ac)
	@test -f $(SWTPM_SRC_DIR)/configure.ac || { \
		echo "error: swtpm sources not found in $(SWTPM_SRC_DIR); run 'git submodule update --init swtpm'" >&2; \
		exit 1; \
	}
	cd $(SWTPM_SRC_DIR) && NOCONFIGURE=1 ./autogen.sh

# Configure swtpm out-of-tree against the local prefix.  The prefix library
# is an order-only prerequisite: refreshing the library alone must not force
# a reconfigure, only header/.pc/configure-input changes do.
$(SWTPM_CONFIGURE_STAMP): $(SWTPM_HEADERS_STAMP) $(LIBTPMS_PC) $(SWTPM_SRC_DIR)/configure | $(PREFIX_RUNTIME_LIB)
	@out=$$(PKG_CONFIG_PATH="$(SWTPM_PKGCONFIG_DIR)" pkg-config --cflags --libs libtpms) || { \
		echo "error: pkg-config cannot resolve libtpms from $(SWTPM_PKGCONFIG_DIR)" >&2; \
		exit 1; \
	}; \
	case "$$out" in \
	*"$(SWTPM_PREFIX)"*) echo "pkg-config resolves local libtpms: $$out" ;; \
	*) echo "error: pkg-config resolved libtpms outside the local prefix: $$out" >&2; exit 1 ;; \
	esac
	@mkdir -p $(SWTPM_BUILD_DIR)
	cd $(SWTPM_BUILD_DIR) && \
	crypto_cppflags=$$(pkg-config --cflags-only-I libcrypto 2>/dev/null || true) && \
	crypto_ldflags=$$(pkg-config --libs-only-L libcrypto 2>/dev/null || true) && \
	PKG_CONFIG_PATH="$(SWTPM_PKGCONFIG_DIR)$${PKG_CONFIG_PATH:+:$$PKG_CONFIG_PATH}" \
	CPPFLAGS="-I$(SWTPM_PREFIX)/include $$crypto_cppflags $(CPPFLAGS)" \
	LDFLAGS="-L$(SWTPM_PREFIX)/lib -Wl,-rpath,$(SWTPM_PREFIX)/lib $$crypto_ldflags $(LDFLAGS)" \
	$(SWTPM_SRC_DIR)/configure --prefix=$(SWTPM_PREFIX) $(SWTPM_CONFIGURE_FLAGS)
	@grep -q "LIBTPMS_LIBS.*-L$(SWTPM_PREFIX)/lib" $(SWTPM_BUILD_DIR)/config.status || { \
		echo "error: swtpm configure resolved libtpms outside $(SWTPM_PREFIX)" >&2; \
		exit 1; \
	}
	@touch $@

# Prepare and configure the isolated swtpm build.  Runs the existing Cargo
# target first (cargo decides whether the Rust library needs rebuilding),
# then updates the prefix/configuration via the file rules above.
prepare-swtpm: $(CARGO_PROFILE_TARGET)
	@test -f $(CARGO_BUILT_LIB) || { \
		echo "error: Cargo-built library $(CARGO_BUILT_LIB) is missing after 'make $(CARGO_PROFILE_TARGET)'" >&2; \
		exit 1; \
	}
	@$(MAKE) --no-print-directory PROFILE=$(PROFILE) \
		$(PREFIX_RUNTIME_LIB) $(SWTPM_CONFIGURE_STAMP)

build-swtpm: prepare-swtpm
	$(MAKE) -C $(SWTPM_BUILD_DIR) -j$(JOBS)
	@$(MAKE) --no-print-directory PROFILE=$(PROFILE) verify-swtpm-linkage

# Check that the real swtpm executable (accounting for libtool wrappers)
# resolves libtpms from the profile-specific prefix, not a system copy, that
# the Rust library exports the complete TIS ABI, and that no swtpm artifact
# leaves a TPM_IO_* symbol as an unresolved dynamic lookup.
verify-swtpm-linkage:
	@bin="$(SWTPM_BUILD_DIR)/src/swtpm/swtpm"; \
	if [ -x "$(SWTPM_BUILD_DIR)/src/swtpm/.libs/swtpm" ]; then \
		bin="$(SWTPM_BUILD_DIR)/src/swtpm/.libs/swtpm"; \
	fi; \
	test -x "$$bin" || { \
		echo "error: swtpm executable not found under $(SWTPM_BUILD_DIR)/src/swtpm; run 'make build-swtpm'" >&2; \
		exit 1; \
	}; \
	deps="$$($(LINK_INSPECT) "$$bin" | grep libtpms || true)"; \
	case "$$deps" in \
	*"$(SWTPM_PREFIX)/lib/"*) \
		echo "verify-swtpm-linkage: OK ($$bin)"; \
		echo "$$deps" ;; \
	*) \
		echo "error: $$bin does not resolve libtpms from $(SWTPM_PREFIX)/lib" >&2; \
		$(LINK_INSPECT) "$$bin" >&2 || true; \
		$(READELF_CMD) "$$bin" >&2 || true; \
		exit 1 ;; \
	esac; \
	consumers="--consumer $$bin"; \
	for lib in "$(SWTPM_BUILD_DIR)"/src/swtpm/.libs/libswtpm*.dylib \
	           "$(SWTPM_BUILD_DIR)"/src/swtpm/.libs/libswtpm*.so*; do \
		[ -f "$$lib" ] && consumers="$$consumers --consumer $$lib"; \
	done; \
	$(PYTHON) scripts/verify_tis_symbols.py \
		--library "$(PREFIX_RUNTIME_LIB)" $$consumers

# Run the complete upstream swtpm test suite with the runtime library path
# pointing at the local prefix (prepended, preserving any existing value).
#
# Upstream test scripts probe the built swtpm and SKIP (exit 77) when it does
# not provide a TPM 1.2/2.0.  For versions the Rust library is supposed to
# provide (SWTPM_REQUIRED_TPM_VERSIONS, matching the crate's default Cargo
# features) such skips mean missing functionality and are promoted to
# failures.  Skips for versions intentionally not compiled in (e.g. 1.2) and
# environment skips (need root, Linux-only, SWTPM_TEST_EXPENSIVE, missing
# optional tools) remain ordinary skips.
SWTPM_REQUIRED_TPM_VERSIONS ?= 2.0
# On failure, dump every test-suite.log and propagate the original status.
test-swtpm: build-swtpm
	@status=0; \
	$(RUNTIME_LIBRARY_PATH_VAR)="$(SWTPM_PREFIX)/lib$${$(RUNTIME_LIBRARY_PATH_VAR):+:$$$(RUNTIME_LIBRARY_PATH_VAR)}" \
		$(MAKE) -C $(SWTPM_BUILD_DIR) check || status=$$?; \
	if [ "$$status" -eq 0 ]; then \
		bad=0; \
		for trs in $$(find $(SWTPM_BUILD_DIR) -name '*.trs'); do \
			grep -q '^:test-result: SKIP' "$$trs" || continue; \
			log="$${trs%.trs}.log"; \
			for ver in $(SWTPM_REQUIRED_TPM_VERSIONS); do \
				if grep -q "does not provide a TPM $$ver" "$$log" 2>/dev/null; then \
					[ "$$bad" -eq 0 ] && echo "error: tests skipped because the Rust libtpms does not provide a required TPM version:" >&2; \
					bad=$$((bad + 1)); \
					name=$${trs##*/}; \
					echo "  $${name%.trs}: $$(grep "does not provide a TPM $$ver" "$$log" | head -1)" >&2; \
				fi; \
			done; \
		done; \
		if [ "$$bad" -ne 0 ]; then \
			echo "error: $$bad test(s) skipped due to missing TPM library functionality; treating as failure" >&2; \
			status=1; \
		fi; \
	fi; \
	if [ "$$status" -ne 0 ]; then \
		echo "test-swtpm: upstream test suite failed (status $$status); dumping test logs" >&2; \
		find $(SWTPM_BUILD_DIR) -name test-suite.log -print -exec cat {} \; ; \
	fi; \
	exit $$status

# Remove only the selected profile's swtpm integration artifacts; the Cargo
# library, the rest of the target directory, and both submodules stay intact.
clean-swtpm:
	rm -rf $(SWTPM_TARGET_DIR)
