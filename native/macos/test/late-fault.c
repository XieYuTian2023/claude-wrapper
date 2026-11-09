#include "../rebind.h"
#include <CoreFoundation/CoreFoundation.h>
#include <assert.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv)
{
    assert(argc == 5);
    unsigned int mode = (unsigned int)strtoul(argv[3], NULL, 10);
    int audit_fd = atoi(argv[4]);
    CFTimeZoneRef zone = CFTimeZoneCopySystem();
    if (zone) CFRelease(zone);
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL); assert(library);
    int (*activate)(void) = dlsym(library, "claude_wrapper_activate");
    int (*get_status)(void *, size_t) = dlsym(library, "claude_wrapper_get_status");
    void (*set_fault)(uint32_t, int) = dlsym(library, "cw_rebind_test_set_fault");
    assert(activate && get_status && set_fault);
    if (mode == 3) {
        assert(!activate());
        set_fault(1, audit_fd);
        // Failure in the new-image callback must occur before this initializer.
        (void)dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
        return 99;
    }
    set_fault(mode, audit_fd);
    int result = activate();
    assert(mode == 1 && result != 0);
    struct claude_wrapper_status status;
    assert(!get_status(&status, sizeof(status)));
    assert(write(audit_fd, &status, sizeof(status)) == sizeof(status));
    return 0;
}
