// Copyright (c) 2013, Facebook, Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//   * Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//   * Neither the name Facebook nor the names of its contributors may be used to
//     endorse or promote products derived from this software without specific
//     prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Derived from Fishhook's Mach-O indirect-symbol traversal. This implementation
// restores and verifies both current and maximum data-page protections per slot.
#include "rebind.h"
#include <dlfcn.h>
#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

static pthread_mutex_t binding_lock = PTHREAD_MUTEX_INITIALIZER;
static struct claude_wrapper_status counters = {
    .abi_version = 2, .struct_size = sizeof(struct claude_wrapper_status)
};
static const struct cw_binding *identity_bindings;
static size_t identity_count;
static const struct mach_header *own_header;
static const struct mach_header *main_header;
static bool registering;
static void *pinned_library;

#ifdef CW_REBIND_TESTING
static _Atomic(uint32_t) test_fault;
static _Atomic(int) test_audit_fd = -1;
// Exists only in the separately compiled test library, never the shipped one.
__attribute__((visibility("default")))
void cw_rebind_test_set_fault(uint32_t fault, int audit_fd)
{
    atomic_store(&test_audit_fd, audit_fd);
    atomic_store(&test_fault, fault);
}
#endif

static kern_return_t restore_page(mach_vm_address_t page, bool maximum, vm_prot_t protection)
{
    kern_return_t result = mach_vm_protect(mach_task_self(), page, vm_page_size, maximum, protection);
#ifdef CW_REBIND_TESTING
    // Restore for real, then simulate the API reporting failure. The child must
    // still terminate, without leaving a writable page alive for the test.
    if (result == KERN_SUCCESS && (atomic_load(&test_fault) & 2)) return KERN_FAILURE;
#endif
    return result;
}

static bool query_page(mach_vm_address_t page, vm_prot_t *current, vm_prot_t *maximum)
{
    mach_vm_address_t address = page;
    mach_vm_size_t length = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t result = mach_vm_region(mach_task_self(), &address, &length,
        VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object);
    if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
    if (result != KERN_SUCCESS || address > page || length < vm_page_size ||
        page - address > length - vm_page_size) return false;
    *current = info.protection;
    *maximum = info.max_protection;
    return true;
}

static bool write_slot(void **slot, void *replacement)
{
#ifdef CW_REBIND_TESTING
    if (atomic_load(&test_fault) & 1) {
        counters.protection_failures++;
        return false;
    }
#endif
    mach_vm_address_t address = (mach_vm_address_t)slot;
    mach_vm_address_t page = address & ~((mach_vm_address_t)vm_page_size - 1);
    vm_prot_t original, maximum;
    if (address % sizeof(void *) || address - page > vm_page_size - sizeof(void *) ||
        !query_page(page, &original, &maximum) || (original & VM_PROT_EXECUTE)) {
        counters.protection_failures++;
        return false;
    }
    bool changed = !(original & VM_PROT_WRITE);
    if (changed) {
        vm_prot_t temporary = original | VM_PROT_WRITE;
        if (!(maximum & VM_PROT_WRITE)) temporary |= VM_PROT_COPY;
        if (mach_vm_protect(mach_task_self(), page, vm_page_size, false, temporary) != KERN_SUCCESS) {
            counters.protection_failures++;
            return false;
        }
    }
    __atomic_store_n(slot, replacement, __ATOMIC_RELEASE);
    counters.stores_performed++;
    bool restored = true;
    if (changed && restore_page(page, false, original) != KERN_SUCCESS)
        restored = false;
    // VM_PROT_COPY may add WRITE to max_protection. Restore that too.
    vm_prot_t current_after, maximum_after;
    if (!query_page(page, &current_after, &maximum_after)) restored = false;
    else if (maximum_after != maximum &&
        restore_page(page, true, maximum) != KERN_SUCCESS)
        restored = false;
    if (!restored) counters.restoration_failures++;
    if (!query_page(page, &current_after, &maximum_after) ||
        current_after != original || maximum_after != maximum ||
        __atomic_load_n(slot, __ATOMIC_ACQUIRE) != replacement) {
        counters.verification_failures++;
        restored = false;
    }
    return restored;
}

static bool file_range(const struct segment_command_64 *segment, uint64_t offset, uint64_t size)
{
    return offset >= segment->fileoff && offset - segment->fileoff <= segment->filesize &&
        size <= segment->filesize - (offset - segment->fileoff);
}

static bool unsupported_layout(const struct mach_header *header)
{
    counters.unsupported_images++;
    counters.parse_failures++;
    if (header == main_header) counters.activation_error = ENOTSUP;
    return header != main_header;
}

static bool bind_image(const struct mach_header *header, intptr_t slide)
{
    const struct mach_header_64 *mh = (const void *)header;
    if (mh->magic != MH_MAGIC_64 || mh->sizeofcmds > UINT32_C(1048576) || mh->ncmds > 4096) {
        return unsupported_layout(header);
    }
#ifdef CPU_SUBTYPE_ARM64E
    if (mh->cputype == CPU_TYPE_ARM64 &&
        (mh->cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E) {
        counters.unsupported_images++;
        if (header == main_header) counters.activation_error = ENOTSUP;
        return header != main_header; // Authenticated GOT slots require separate PAC handling.
    }
#endif
    const struct segment_command_64 *linkedit = NULL;
    const struct symtab_command *symbols = NULL;
    const struct dysymtab_command *indirect = NULL;
    const unsigned char *commands = (const void *)(mh + 1);
    size_t offset = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (offset > mh->sizeofcmds || mh->sizeofcmds - offset < sizeof(struct load_command)) return unsupported_layout(header);
        const struct load_command *command = (const void *)(commands + offset);
        if (command->cmdsize < sizeof(*command) || command->cmdsize > mh->sizeofcmds - offset) return unsupported_layout(header);
        if (command->cmd == LC_SEGMENT_64 && command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment = (const void *)command;
            if (!strncmp(segment->segname, SEG_LINKEDIT, 16)) linkedit = segment;
        } else if (command->cmd == LC_SYMTAB && command->cmdsize >= sizeof(struct symtab_command))
            symbols = (const void *)command;
        else if (command->cmd == LC_DYSYMTAB && command->cmdsize >= sizeof(struct dysymtab_command))
            indirect = (const void *)command;
        offset += command->cmdsize;
    }
    if (!linkedit || !symbols || !indirect || !indirect->nindirectsyms) return true;
    if (!file_range(linkedit, symbols->symoff, (uint64_t)symbols->nsyms * sizeof(struct nlist_64)) ||
        !file_range(linkedit, symbols->stroff, symbols->strsize) ||
        !file_range(linkedit, indirect->indirectsymoff, (uint64_t)indirect->nindirectsyms * sizeof(uint32_t))) return unsupported_layout(header);
    uintptr_t base = (uintptr_t)slide + linkedit->vmaddr - linkedit->fileoff;
    const struct nlist_64 *symtab = (const void *)(base + symbols->symoff);
    const char *strings = (const void *)(base + symbols->stroff);
    const uint32_t *indices = (const void *)(base + indirect->indirectsymoff);
    offset = 0;
    bool success = true;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *command = (const void *)(commands + offset);
        offset += command->cmdsize;
        if (command->cmd != LC_SEGMENT_64 || command->cmdsize < sizeof(struct segment_command_64)) continue;
        const struct segment_command_64 *segment = (const void *)command;
        if (strncmp(segment->segname, SEG_DATA, 16) && strncmp(segment->segname, "__DATA_CONST", 16)) continue;
        if (segment->initprot & VM_PROT_EXECUTE) continue;
        if (segment->nsects > (command->cmdsize - sizeof(*segment)) / sizeof(struct section_64)) return unsupported_layout(header);
        const struct section_64 *sections = (const void *)(segment + 1);
        for (uint32_t j = 0; j < segment->nsects; j++) {
            const struct section_64 *section = &sections[j];
            uint32_t type = section->flags & SECTION_TYPE;
            if (type != S_LAZY_SYMBOL_POINTERS && type != S_NON_LAZY_SYMBOL_POINTERS) continue;
            if (section->addr < segment->vmaddr || section->addr - segment->vmaddr > segment->vmsize ||
                section->size > segment->vmsize - (section->addr - segment->vmaddr) || section->size % sizeof(void *)) return unsupported_layout(header);
            size_t count = section->size / sizeof(void *);
            if (section->reserved1 > indirect->nindirectsyms || count > indirect->nindirectsyms - section->reserved1) return unsupported_layout(header);
            void **slots = (void **)((uintptr_t)slide + section->addr);
            for (size_t k = 0; k < count; k++) {
                uint32_t index = indices[section->reserved1 + k];
                if (index & (INDIRECT_SYMBOL_ABS | INDIRECT_SYMBOL_LOCAL)) continue;
                if (index >= symbols->nsyms || symtab[index].n_un.n_strx >= symbols->strsize) return unsupported_layout(header);
                uint32_t start = symtab[index].n_un.n_strx;
                const char *name = strings + start;
                if (!memchr(name, 0, symbols->strsize - start)) return unsupported_layout(header);
                if (*name != '_') continue;
                for (size_t b = 0; b < identity_count; b++) {
                    if (strcmp(name + 1, identity_bindings[b].name)) continue;
                    counters.slots_matched++;
                    if (header == main_header) counters.main_slots_matched++;
                    if (__atomic_load_n(&slots[k], __ATOMIC_ACQUIRE) == identity_bindings[b].replacement)
                        counters.slots_already_bound++;
                    else if (write_slot(&slots[k], identity_bindings[b].replacement)) {
                        counters.slots_written++;
                        if (header == main_header) counters.main_slots_written++;
                    } else {
                        counters.slots_failed++;
                        if (header == main_header) counters.main_slots_failed++;
                        success = false;
                    }
                    break;
                }
            }
        }
    }
    return success;
}

static void image_added(const struct mach_header *header, intptr_t slide)
{
    pthread_mutex_lock(&binding_lock);
    counters.image_callbacks++;
    if (header == own_header) { pthread_mutex_unlock(&binding_lock); return; }
    counters.images_examined++;
    uint64_t failures_before = counters.slots_failed;
    bool success = bind_image(header, slide);
    // A later unsupported section must not hide an earlier failed write.
    if (counters.slots_failed != failures_before) success = false;
    bool restoration_failed = counters.restoration_failures || counters.verification_failures;
    if (!success && !counters.activation_error) counters.activation_error = EACCES;
    bool fatal = restoration_failed || (!registering && !success);
    pthread_mutex_unlock(&binding_lock);
    if (fatal) {
#ifdef CW_REBIND_TESTING
        int audit_fd = atomic_load(&test_audit_fd);
        if (audit_fd >= 0) (void)write(audit_fd, &counters, sizeof(counters));
#endif
        static const char message[] = "identity-native: identity import binding failed\n";
        (void)write(STDERR_FILENO, message, sizeof(message) - 1);
        _exit(126);
    }
}

int cw_rebind_start(const struct cw_binding *bindings, size_t count)
{
    if (!bindings || !count) return EINVAL;
    Dl_info info;
    if (!dladdr((const void *)cw_rebind_start, &info)) return ENOENT;
    // dyld callbacks have no unregister operation; keep their code mapped.
    pinned_library = dlopen(info.dli_fname, RTLD_NOW | RTLD_NODELETE);
    if (!pinned_library) return ENOENT;
    own_header = info.dli_fbase;
    main_header = _dyld_get_image_header(0);
    identity_bindings = bindings;
    identity_count = count;
    registering = true;
    _dyld_register_func_for_add_image(image_added); // Also synchronously visits current images.
    pthread_mutex_lock(&binding_lock);
    registering = false;
    counters.active = counters.activation_error == 0;
    int result = (int)counters.activation_error;
    pthread_mutex_unlock(&binding_lock);
    return result;
}

int cw_rebind_status(struct claude_wrapper_status *status)
{
    if (!status) return EINVAL;
    pthread_mutex_lock(&binding_lock);
    *status = counters;
    pthread_mutex_unlock(&binding_lock);
    return 0;
}
