CC := clang
CFLAGS ?= -O2
ARCHS ?= $(shell uname -m)
ARCH_FLAGS := $(foreach arch,$(ARCHS),-arch $(arch))
BUILD ?= build
MACOSX_DEPLOYMENT_TARGET ?= 11.0

.PHONY: all clean test
all: $(BUILD)/socket-guard

$(BUILD)/socket-guard: socket_guard.c identity_files.h ../diagnostics.h
	mkdir -p "$(BUILD)"
	$(CC) $(CFLAGS) $(ARCH_FLAGS) -mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET) -std=c11 -Wall -Wextra -Werror -Wno-deprecated-declarations $(LDFLAGS) -o "$@" "$<"

test: all
	python3 test_socket_guard.py

clean:
	rm -f "$(BUILD)/socket-guard"
