#ifndef CLAUDE_WRAPPER_REBIND_H
#define CLAUDE_WRAPPER_REBIND_H
#include <stddef.h>
#include <stdint.h>

// Public, fixed-width ABI. New versions must change abi_version/struct_size.
struct claude_wrapper_status {
    uint64_t abi_version;
    uint64_t struct_size;
    uint64_t activation_error;
    uint64_t self_test_mask;
    uint64_t image_callbacks;
    uint64_t images_examined;
    uint64_t unsupported_images;
    uint64_t parse_failures;
    uint64_t slots_matched;
    uint64_t stores_performed;
    uint64_t slots_written; // Written AND current/max permissions restored and verified.
    uint64_t slots_already_bound;
    uint64_t slots_failed;
    uint64_t protection_failures;
    uint64_t restoration_failures;
    uint64_t verification_failures;
    uint64_t main_slots_matched;
    uint64_t main_slots_written;
    uint64_t main_slots_failed;
    uint64_t active;
};

// Returns errno-style status; does not write or close a readiness descriptor.
__attribute__((visibility("default"))) int claude_wrapper_activate(void);
__attribute__((visibility("default"))) uint32_t claude_wrapper_self_test(void);
__attribute__((visibility("default"))) int claude_wrapper_get_status(void *buffer, size_t size);
// After JS has validated startup state, publish the relay/restore BUN_OPTIONS
// in C environ and clear private bootstrap variables. Idempotent; no fd writes.
__attribute__((visibility("default"))) int claude_wrapper_clear_bootstrap(void);
#define CLAUDE_WRAPPER_SELF_TEST_ALL UINT32_C(224)

// Internal identity-only import-binding interface.
struct cw_binding { const char *name; void *replacement; };
__attribute__((visibility("hidden"))) int cw_rebind_start(const struct cw_binding *bindings, size_t count);
__attribute__((visibility("hidden"))) int cw_rebind_status(struct claude_wrapper_status *status);
#endif
