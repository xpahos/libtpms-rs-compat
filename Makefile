PYTHON          ?= python3
CARGO           ?= cargo
LIBTPMS_HEADER  := libtpms/include/libtpms/tpm_library.h
.DEFAULT_GOAL   := check

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
DYLIB_NAME               := libtpms.dylib
LIBTPMS_RUNTIME_NAME     := libtpms.0.dylib
RUNTIME_LIBRARY_PATH_VAR := DYLD_LIBRARY_PATH
LINK_INSPECT             := otool -L
READELF_CMD              := true
LIB_ID_FIXUP              = install_name_tool -id "$(PREFIX_RUNTIME_LIB)" "$(PREFIX_RUNTIME_LIB)"
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
FFI_TYPES       := src/types/mod.rs

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

CARGO_TARGET_DIR ?= $(CURDIR)/target
export CARGO_TARGET_DIR
PROFILE ?= debug

ifeq ($(PROFILE),debug)
CARGO_BUILD_FLAGS :=
else ifeq ($(PROFILE),release)
CARGO_BUILD_FLAGS := --release
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
LIBTPMS_PC_VERSION     := 0.10.2

CARGO_BUILT_LIB     := $(PROFILE_TARGET_DIR)/$(LIBTPMS_BUILD_NAME)
SWTPM_PKGCONFIG_DIR := $(SWTPM_PREFIX)/lib/pkgconfig
LIBTPMS_PC          := $(SWTPM_PKGCONFIG_DIR)/libtpms.pc
PREFIX_LIB          := $(SWTPM_PREFIX)/lib/$(LIBTPMS_BUILD_NAME)
PREFIX_RUNTIME_LIB  := $(SWTPM_PREFIX)/lib/$(LIBTPMS_RUNTIME_NAME)

SWTPM_HEADERS_STAMP   := $(SWTPM_TARGET_DIR)/.headers-installed
SWTPM_CONFIGURE_STAMP := $(SWTPM_TARGET_DIR)/.configured

JOBS ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)

########################## Build and validation ###################

.PHONY: build generate-abi test-abi-tools test-abi test-rust check clean

build:
	$(CARGO) build $(CARGO_BUILD_FLAGS)
	@echo "built: $(PROFILE_TARGET_DIR)/$(DYLIB_NAME)"

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

test-abi-tools:
	$(PYTHON) -m unittest discover -s scripts/tests

test-abi: test-abi-tools
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
	$(PYTHON) $(ABI_GENERATOR) \
		--header $(LIBTPMS_HEADER) \
		--check-ffi-types $(FFI_TYPES)
	@test -f $(NVMARSHAL_SOURCE) || { \
		echo "error: $(NVMARSHAL_SOURCE) not found; run 'git submodule update --init libtpms'" >&2; \
		exit 1; \
	}
	$(PYTHON) $(PA_FIXTURE_GENERATOR) --check
	@test -f $(TPM2_GLOBAL_HEADER) || { \
		echo "error: $(TPM2_GLOBAL_HEADER) not found; run 'git submodule update --init libtpms'" >&2; \
		exit 1; \
	}
	$(PYTHON) $(NV_LAYOUT_FIXTURE_GENERATOR) --check
	@test -f $(CRYPTRAND_SOURCE) || { \
		echo "error: $(CRYPTRAND_SOURCE) not found; run 'git submodule update --init libtpms'" >&2; \
		exit 1; \
	}
	$(PYTHON) $(DRBG_FIXTURE_GENERATOR) --check --quiet
	$(PYTHON) $(VOLATILE_FIXTURE_GENERATOR) --check
	@test -f $(TICKET_SOURCE) || { \
		echo "error: $(TICKET_SOURCE) not found; run 'git submodule update --init libtpms'" >&2; \
		exit 1; \
	}
	$(PYTHON) $(HASH_FIXTURE_GENERATOR) --check --quiet
	@test -f $(ALGORITHM_TESTS_SOURCE) || { \
		echo "error: $(ALGORITHM_TESTS_SOURCE) not found; run 'git submodule update --init libtpms'" >&2; \
		exit 1; \
	}
	$(PYTHON) $(CANCEL_FIXTURE_GENERATOR) --check
	@test -f $(EXEC_COMMAND_SOURCE) || { \
		echo "error: $(EXEC_COMMAND_SOURCE) not found; run 'git submodule update --init libtpms'" >&2; \
		exit 1; \
	}
	$(PYTHON) $(FAILURE_LOCATIONS_FIXTURE_GENERATOR) --check

test-rust:
	$(CARGO) check
	$(CARGO) test --all-features

check: golden-audit test-abi test-rust

clean:
	$(CARGO) clean

########################## Golden tests ###################

GOLDEN := $(PYTHON) scripts/golden_responses/golden.py

.PHONY: golden-audit test-golden update-golden update-golden-all

golden-audit:
	$(GOLDEN) audit

test-golden:
	$(GOLDEN) verify --all
	$(PYTHON) -m unittest scripts.tests.golden_docker_checks

update-golden:
	@test -n "$(FAMILY)" || { \
		echo "usage: make update-golden FAMILY=create-primary"; \
		exit 2; \
	}
	$(GOLDEN) update "$(FAMILY)"

update-golden-all:
	$(GOLDEN) update --all --confirm-reference-update

########################## swtpm tests ###################

.PHONY: test-swtpm test-swtpm-docker clean-swtpm

$(CARGO_BUILT_LIB): build
	@test -f $@ || { \
		echo "error: make build PROFILE=$(PROFILE) did not produce $@" >&2; \
		exit 1; \
	}

$(PREFIX_RUNTIME_LIB): $(CARGO_BUILT_LIB)
	@mkdir -p $(SWTPM_PREFIX)/lib
	cp -f $(CARGO_BUILT_LIB) $(PREFIX_RUNTIME_LIB)
	$(LIB_ID_FIXUP)
	ln -sf $(LIBTPMS_RUNTIME_NAME) $(PREFIX_LIB)

$(SWTPM_HEADERS_STAMP): $(LIBTPMS_PUBLIC_HEADERS)
	@test -n "$(LIBTPMS_PUBLIC_HEADERS)" || { \
		echo "error: no libtpms headers found in $(LIBTPMS_INCLUDE_DIR); run 'git submodule update --init libtpms'" >&2; \
		exit 1; \
	}
	@mkdir -p $(SWTPM_PREFIX)/include/libtpms $(SWTPM_TARGET_DIR)
	cp -f $(LIBTPMS_PUBLIC_HEADERS) $(SWTPM_PREFIX)/include/libtpms/
	@touch $@

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

$(SWTPM_SRC_DIR)/configure: $(wildcard $(SWTPM_SRC_DIR)/configure.ac)
	@test -f $(SWTPM_SRC_DIR)/configure.ac || { \
		echo "error: swtpm sources not found in $(SWTPM_SRC_DIR); run 'git submodule update --init swtpm'" >&2; \
		exit 1; \
	}
	cd $(SWTPM_SRC_DIR) && NOCONFIGURE=1 ./autogen.sh

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

SWTPM_REQUIRED_TPM_VERSIONS ?= 2.0

test-swtpm: $(SWTPM_CONFIGURE_STAMP)
	$(MAKE) -C $(SWTPM_BUILD_DIR) -j$(JOBS)
	@bin="$(SWTPM_BUILD_DIR)/src/swtpm/swtpm"; \
	if [ -x "$(SWTPM_BUILD_DIR)/src/swtpm/.libs/swtpm" ]; then \
		bin="$(SWTPM_BUILD_DIR)/src/swtpm/.libs/swtpm"; \
	fi; \
	test -x "$$bin" || { \
		echo "error: swtpm build did not produce an executable under $(SWTPM_BUILD_DIR)/src/swtpm" >&2; \
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

clean-swtpm:
	rm -rf $(SWTPM_TARGET_DIR)

DOCKER                            ?= docker
DOCKER_PLATFORM                   ?=
SWTPM_DOCKER_IMAGE                ?= libtpms-rs-compat-test-swtpm
SWTPM_DOCKER_DOCKERFILE           := Dockerfile.test-swtpm
SWTPM_DOCKER_RUNNER               := scripts/test-swtpm-docker.sh
SWTPM_DOCKER_TARGET_VOLUME_PREFIX ?= libtpms-rs-compat-target
SWTPM_DOCKER_REGISTRY_VOLUME      ?= libtpms-rs-compat-cargo-registry
SWTPM_DOCKER_GIT_VOLUME           ?= libtpms-rs-compat-cargo-git
DOCKER_PLATFORM_FLAG              := $(if $(DOCKER_PLATFORM),--platform "$(DOCKER_PLATFORM)")

test-swtpm-docker:
	$(DOCKER) build $(DOCKER_PLATFORM_FLAG) \
		--file "$(SWTPM_DOCKER_DOCKERFILE)" \
		--target swtpm \
		--tag "$(SWTPM_DOCKER_IMAGE)" \
		"$(CURDIR)"
	@set -eu; \
	image_id="$$($(DOCKER) image inspect --format '{{.Id}}' "$(SWTPM_DOCKER_IMAGE)")"; \
	platform="$$($(DOCKER) image inspect --format '{{.Os}}-{{.Architecture}}' "$(SWTPM_DOCKER_IMAGE)")"; \
	repository_id="$$(printf '%s' "$(CURDIR)" | cksum | awk '{print $$1}')"; \
	target_volume="$(SWTPM_DOCKER_TARGET_VOLUME_PREFIX)-$$repository_id-$$platform"; \
	interfaces=; \
	[ ! -c /dev/cuse ] || interfaces=CUSE; \
	[ ! -c /dev/vtpmx ] || interfaces="$${interfaces:+$$interfaces, }vTPM-proxy"; \
	docker_device_args=; \
	if [ -n "$$interfaces" ]; then \
		docker_device_args="--privileged --volume /dev:/dev"; \
		echo "test-swtpm-docker: enabling privileged container for $$interfaces"; \
	else \
		echo "test-swtpm-docker: /dev/cuse and /dev/vtpmx are unavailable; kernel-interface tests may skip"; \
	fi; \
	$(DOCKER) run --rm --init $(DOCKER_PLATFORM_FLAG) $$docker_device_args \
		-v "$(CURDIR):/repo:ro" \
		-v "$$target_volume:/cache/target" \
		-v "$(SWTPM_DOCKER_REGISTRY_VOLUME):/usr/local/cargo/registry" \
		-v "$(SWTPM_DOCKER_GIT_VOLUME):/usr/local/cargo/git" \
		-e "PROFILE=$(PROFILE)" \
		-e "SWTPM_TEST_IBMTSS2=1" \
		-e "SWTPM_TEST_EXPENSIVE=1" \
		-e "SWTPM_DOCKER_IMAGE_ID=$$image_id" \
		"$(SWTPM_DOCKER_IMAGE)" /repo/$(SWTPM_DOCKER_RUNNER)
