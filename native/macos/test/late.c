#include "../rebind.h"
#include <CoreFoundation/CoreFoundation.h>
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stdbool.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct page_state { mach_vm_address_t address; vm_prot_t current, maximum; };
static struct page_state pages[8192];
static size_t pages_count;
static bool tracking_failed;
static bool page_permissions(mach_vm_address_t page, vm_prot_t *current, vm_prot_t *maximum)
{
    mach_vm_address_t address = page;
    mach_vm_size_t length = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t r = mach_vm_region(mach_task_self(), &address, &length,
        VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object);
    if (object) mach_port_deallocate(mach_task_self(), object);
    if (r != KERN_SUCCESS || address > page || page - address >= length) return false;
    *current = info.protection; *maximum = info.max_protection; return true;
}
static void capture_image(const struct mach_header *header, intptr_t slide)
{
    const struct mach_header_64 *mh = (const void *)header;
    if (mh->magic != MH_MAGIC_64) return;
    const unsigned char *cursor = (const void *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *command = (const void *)cursor;
        cursor += command->cmdsize;
        if (command->cmd != LC_SEGMENT_64) continue;
        const struct segment_command_64 *segment = (const void *)command;
        if (strncmp(segment->segname, "__DATA", 16) && strncmp(segment->segname, "__DATA_CONST", 16)) continue;
        const struct section_64 *section = (const void *)(segment + 1);
        for (uint32_t j = 0; j < segment->nsects; j++) {
            uint32_t type = section[j].flags & SECTION_TYPE;
            if (type != S_LAZY_SYMBOL_POINTERS && type != S_NON_LAZY_SYMBOL_POINTERS) continue;
            mach_vm_address_t start = ((uintptr_t)slide + section[j].addr) & ~((mach_vm_address_t)vm_page_size - 1);
            mach_vm_address_t end = (uintptr_t)slide + section[j].addr + section[j].size;
            for (mach_vm_address_t page = start; page < end; page += vm_page_size) {
                bool existing = false;
                for (size_t k = 0; k < pages_count; k++) if (pages[k].address == page) existing = true;
                if (existing) continue;
                if (pages_count == sizeof(pages)/sizeof(pages[0])) { tracking_failed = true; return; }
                struct page_state value = { .address = page };
                if (!page_permissions(page, &value.current, &value.maximum)) { tracking_failed = true; return; }
                pages[pages_count++] = value;
            }
        }
    }
}
static bool permissions_unchanged(void)
{
    if (tracking_failed || !pages_count) return false;
    for (size_t i = 0; i < pages_count; i++) {
        vm_prot_t current, maximum;
        if (!page_permissions(pages[i].address, &current, &maximum) ||
            current != pages[i].current || maximum != pages[i].maximum) return false;
    }
    return true;
}
int main(int argc, char **argv)
{
    assert(argc == 5);
    int ready[2]; assert(!pipe(ready));
    assert(fcntl(ready[0], F_SETFL, O_NONBLOCK) != -1);
    char descriptor[32]; snprintf(descriptor, sizeof(descriptor), "%d", ready[1]);
    assert(!setenv("CLAUDE_WRAPPER_READY_FD", descriptor, 1));
    assert(!setenv("CLAUDE_WRAPPER_INIT_OWNER", "bun", 1));
    int (*saved_hostname)(char *, size_t) = dlsym(RTLD_DEFAULT, "gethostname");
    char host_before[256];
    assert(!saved_hostname(host_before, sizeof(host_before)));
    struct passwd *account = getpwuid(getuid());
    assert(account && account->pw_name);
    char *user_before = strdup(account->pw_name);
    assert(user_before);
    void *saved_open = dlsym(RTLD_DEFAULT, "open");
    void *saved_read = dlsym(RTLD_DEFAULT, "read");
    void *saved_write = dlsym(RTLD_DEFAULT, "write");
    struct stat before, after; assert(!stat(argv[4], &before));
    void *old_consumer = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL); assert(old_consumer);
    uint32_t (*old_probe)(void) = dlsym(old_consumer, "cw_consumer_probe"); assert(old_probe);
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL); assert(library);
    int (*activate)(void) = dlsym(library, "claude_wrapper_activate");
    int (*status_fn)(void *, size_t) = dlsym(library, "claude_wrapper_get_status");
    uint32_t (*self_test)(void) = dlsym(library, "claude_wrapper_self_test");
    int (*clear)(void) = dlsym(library, "claude_wrapper_clear_bootstrap");
    assert(activate && status_fn && self_test && clear);
    char ack; assert(read(ready[0], &ack, 1) == -1 && errno == EAGAIN);
    assert(fcntl(ready[1], F_GETFD) != -1);
    _dyld_register_func_for_add_image(capture_image);
    int activation = activate();
    struct claude_wrapper_status status;
    assert(!status_fn(&status, sizeof(status)));
    if (activation) {
        fprintf(stderr, "activation=%d unsupported=%llu parse=%llu matched=%llu written=%llu failed=%llu protect=%llu restore=%llu verify=%llu\n",
            activation, status.unsupported_images, status.parse_failures, status.slots_matched,
            status.slots_written, status.slots_failed, status.protection_failures,
            status.restoration_failures, status.verification_failures);
        return 1;
    }
    assert(status.abi_version == 2 && status.struct_size == sizeof(status));
    assert(status.slots_written && status.main_slots_written && !status.slots_failed);
    assert(status.stores_performed == status.slots_written);
    assert(self_test() == CLAUDE_WRAPPER_SELF_TEST_ALL);
    assert(old_probe() == CLAUDE_WRAPPER_SELF_TEST_ALL);
    CFTimeZoneRef zone = CFTimeZoneCopySystem();
    CFStringRef expected = CFStringCreateWithCString(NULL, getenv("TZ"), kCFStringEncodingUTF8);
    assert(zone && expected && CFEqual(CFTimeZoneGetName(zone), expected));
    CFRelease(zone);
    CFRelease(expected);
    assert(permissions_unchanged());
    uint64_t first_writes = status.slots_written;
    assert(!activate());
    assert(!status_fn(&status, sizeof(status)) && status.slots_written == first_writes);
    assert(permissions_unchanged());
    char host[256];
    assert(!gethostname(host, sizeof(host)) && !strcmp(host, host_before));
    account = getpwuid(getuid());
    assert(account && !strcmp(account->pw_name, user_before));
    free(user_before);
    assert(dlsym(RTLD_DEFAULT, "gethostname") == (void *)saved_hostname);
    assert(!clear() && self_test() == CLAUDE_WRAPPER_SELF_TEST_ALL);
    assert(!getenv("CLAUDE_WRAPPER_ACCOUNT_HOME") && !getenv("CLAUDE_WRAPPER_HOSTNAME") && !getenv("CLAUDE_WRAPPER_INIT_OWNER"));
    void *new_consumer = dlopen(argv[3], RTLD_NOW | RTLD_LOCAL); assert(new_consumer);
    uint32_t (*new_probe)(void) = dlsym(new_consumer, "cw_consumer_probe");
    uint32_t (*constructor_probe)(void) = dlsym(new_consumer, "cw_consumer_constructor");
    assert(new_probe && constructor_probe && new_probe() == CLAUDE_WRAPPER_SELF_TEST_ALL && constructor_probe() == CLAUDE_WRAPPER_SELF_TEST_ALL);
    assert(permissions_unchanged());
    assert(self_test() == CLAUDE_WRAPPER_SELF_TEST_ALL);
    assert(read(ready[0], &ack, 1) == -1 && errno == EAGAIN && fcntl(ready[1], F_GETFD) != -1);
    assert(dlsym(RTLD_DEFAULT, "open") == saved_open && dlsym(RTLD_DEFAULT, "read") == saved_read && dlsym(RTLD_DEFAULT, "write") == saved_write);
    int fd = open(argv[4], O_WRONLY | O_TRUNC); assert(fd >= 0);
    assert(write(fd, "native host I/O\n", 16) == 16 && !close(fd));
    assert(!stat(argv[4], &after) && before.st_ino == after.st_ino && before.st_dev == after.st_dev);
    assert(!status_fn(&status, sizeof(status)));
    printf("{\"selfTest\":224,\"existingConsumer\":true,\"futureConstructor\":true,\"systemHostAndUserPreserved\":true,\"pageCurrentAndMaxRestored\":true,\"sameFileFunctionsAndInode\":true,\"bunOwnsReady\":true,\"slotsWritten\":%llu,\"slotsFailed\":%llu,\"mainSlotsWritten\":%llu,\"unsupportedImages\":%llu}\n",
        status.slots_written, status.slots_failed, status.main_slots_written, status.unsupported_images);
    close(ready[0]); close(ready[1]);
    return 0;
}
