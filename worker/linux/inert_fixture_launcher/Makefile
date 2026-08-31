CC ?= cc
BUILD_DIR ?= ../../../build/native/inert_fixture_launcher
TARGET := $(BUILD_DIR)/bpe-inert-fixture-launcher
SECCOMP_DUMPER := $(BUILD_DIR)/seccomp-policy-dump
SECCOMP_BYTES := $(BUILD_DIR)/seccomp-policy.bin
PROTOCOL_TEST := $(BUILD_DIR)/protocol-golden-test
DESCRIPTOR_SCAN_TEST := $(BUILD_DIR)/descriptor-scan-test
SOURCE := launcher.c
HEADERS := protocol.h seccomp_filter.h seccomp_policy.h seccomp_policy_digest.h wire.h

CPPFLAGS := -I.
CFLAGS := -std=c17 -O2 -g0 -Wall -Wextra -Werror -Wpedantic \
	-fPIE -fstack-protector-strong -fno-strict-aliasing -D_FORTIFY_SOURCE=3
LDFLAGS := -static-pie -Wl,-z,relro,-z,now,-z,noexecstack,--fatal-warnings \
	-Wl,--build-id=sha1

.PHONY: all clean check check-descriptor-scan check-protocol check-static verify-seccomp-digest

all: $(TARGET)

$(TARGET): $(SOURCE) $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCE) $(LDFLAGS) -o $@

$(SECCOMP_DUMPER): seccomp_policy_dump.c seccomp_filter.h seccomp_policy.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) seccomp_policy_dump.c -o $@

$(PROTOCOL_TEST): protocol_golden_test.c protocol.h wire.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) protocol_golden_test.c -o $@

$(DESCRIPTOR_SCAN_TEST): descriptor_scan_test.c $(SOURCE) $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) descriptor_scan_test.c -o $@

$(BUILD_DIR):
	mkdir -p $@

verify-seccomp-digest: $(SECCOMP_DUMPER)
	@$(SECCOMP_DUMPER) > $(SECCOMP_BYTES)
	@actual="$$(sha256sum $(SECCOMP_BYTES) | awk '{print $$1}')"; \
	expected="$$(sed -n 's/.*"\([0-9a-f]\{64\}\)".*/\1/p' seccomp_policy_digest.h)"; \
	test -n "$$expected"; \
	test "$$actual" = "$$expected"

check-protocol: $(PROTOCOL_TEST)
	@$(PROTOCOL_TEST)

check-descriptor-scan: $(DESCRIPTOR_SCAN_TEST)
	@$(DESCRIPTOR_SCAN_TEST)

check-static: $(TARGET)
	@readelf -hW $(TARGET) | grep -q 'Class:[[:space:]]*ELF64'
	@readelf -hW $(TARGET) | grep -q "Data:[[:space:]]*2's complement, little endian"
	@readelf -hW $(TARGET) | grep -q 'Type:[[:space:]]*DYN (Position-Independent Executable file)'
	@readelf -hW $(TARGET) | grep -q 'Machine:[[:space:]]*Advanced Micro Devices X86-64'
	@! readelf -lW $(TARGET) | grep -q ' INTERP '
	@! readelf -dW $(TARGET) | grep -Eq '\((NEEDED|RPATH|RUNPATH)\)'
	@readelf -lW $(TARGET) | awk '$$1 == "GNU_STACK" { seen = 1; if ($$7 ~ /E/) exit 1 } END { if (!seen) exit 1 }'
	@readelf -lW $(TARGET) | grep -q ' GNU_RELRO '
	@readelf -dW $(TARGET) | grep -Eq '\(FLAGS\).*BIND_NOW'
	@readelf -dW $(TARGET) | grep -Eq '\(FLAGS_1\).*NOW PIE'
	@readelf -nW $(TARGET) | grep -Eq 'Build ID: [0-9a-f]{40}$$'
	@file $(TARGET) | grep -q 'static-pie linked'
	@expected="$$(sed -n 's/^#define BPE_INERT_SECCOMP_POLICY_ID "\(.*\)"$$/\1/p' seccomp_policy.h)"; \
	test -n "$$expected"; strings -a $(TARGET) | grep -Fqx "$$expected"
	@expected="$$(sed -n 's/.*"\([0-9a-f]\{64\}\)".*/\1/p' seccomp_policy_digest.h)"; \
	test -n "$$expected"; strings -a $(TARGET) | grep -Fqx "$$expected"

check: verify-seccomp-digest check-protocol check-descriptor-scan $(TARGET) check-static

clean:
	rm -f $(TARGET) $(SECCOMP_DUMPER) $(SECCOMP_BYTES) $(PROTOCOL_TEST) \
		$(DESCRIPTOR_SCAN_TEST)
