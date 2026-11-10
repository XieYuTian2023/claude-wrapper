CC := clang
ARCHS ?= $(shell uname -m)
ARCH_FLAGS := $(foreach arch,$(ARCHS),-arch $(arch))
BUILD ?= build
CFLAGS ?= -O2 -Wall -Wextra -Werror
MACOSX_DEPLOYMENT_TARGET ?= 11.0
PLATFORM_FLAGS := $(ARCH_FLAGS) -mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET)

.PHONY: all test test-late test-late-faults test-late-official clean
all: $(BUILD)/identity-launch $(BUILD)/libclaude-wrapper.dylib $(BUILD)/identity.cjs

$(BUILD):
	mkdir -p "$@"

$(BUILD)/libclaude-wrapper.dylib: identity.m rebind.c rebind.h ../diagnostics.h LICENSE.fishhook | $(BUILD)
	$(CC) $(CFLAGS) $(PLATFORM_FLAGS) -fobjc-arc -dynamiclib \
		-framework Foundation -o "$@" identity.m rebind.c

$(BUILD)/identity-launch: launch.c ../diagnostics.h | $(BUILD)
	$(CC) $(CFLAGS) $(PLATFORM_FLAGS) \
		-framework CoreFoundation -framework Security -o "$@" "$<"

$(BUILD)/identity.cjs: ../bun/identity.cjs | $(BUILD)
	cp "$<" "$@"

$(BUILD)/identity-fixture: test/fixture.m | $(BUILD)
	$(CC) $(CFLAGS) $(PLATFORM_FLAGS) -fobjc-arc \
		-framework Foundation -o "$@" "$<"

test: all $(BUILD)/identity-fixture $(BUILD)/late-fixture $(BUILD)/late-consumer.dylib $(BUILD)/libclaude-wrapper-test.dylib $(BUILD)/late-fault-fixture
	./test/check.sh "$(abspath $(BUILD))"
	python3 test/check-late.py "$(abspath $(BUILD))"
	python3 test/check-late-faults.py "$(abspath $(BUILD))"

clean:
	rm -f "$(BUILD)/identity-launch" "$(BUILD)/libclaude-wrapper.dylib" "$(BUILD)/identity-fixture" "$(BUILD)/identity.cjs" "$(BUILD)/late-fixture" "$(BUILD)/late-consumer.dylib" "$(BUILD)/libclaude-wrapper-test.dylib" "$(BUILD)/late-fault-fixture"

$(BUILD)/late-consumer.dylib: test/late-consumer.m | $(BUILD)
	$(CC) $(CFLAGS) $(PLATFORM_FLAGS) -fobjc-arc -dynamiclib -framework Foundation -o "$@" "$<"

$(BUILD)/late-fixture: test/late.c rebind.h | $(BUILD)
	$(CC) $(CFLAGS) $(PLATFORM_FLAGS) -framework CoreFoundation -o "$@" "$<"

test-late: all $(BUILD)/late-fixture $(BUILD)/late-consumer.dylib
	python3 test/check-late.py "$(abspath $(BUILD))"

test-late-official: all $(BUILD)/late-consumer.dylib
	python3 test/check-late-official.py

$(BUILD)/libclaude-wrapper-test.dylib: identity.m rebind.c rebind.h ../diagnostics.h | $(BUILD)
	$(CC) $(CFLAGS) $(PLATFORM_FLAGS) -DCW_REBIND_TESTING -fobjc-arc -dynamiclib \
		-framework Foundation -o "$@" identity.m rebind.c

$(BUILD)/late-fault-fixture: test/late-fault.c rebind.h | $(BUILD)
	$(CC) $(CFLAGS) $(PLATFORM_FLAGS) -framework CoreFoundation -o "$@" "$<"

test-late-faults: all $(BUILD)/libclaude-wrapper-test.dylib $(BUILD)/late-fault-fixture $(BUILD)/late-consumer.dylib
	python3 test/check-late-faults.py "$(abspath $(BUILD))"
