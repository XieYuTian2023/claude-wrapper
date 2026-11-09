#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define READY_FD "CLAUDE_WRAPPER_READY_FD"
#define SHIM_NAME "libclaude-wrapper.dylib"
#define READY_TIMEOUT_MS 5000

// CodeDirectory flags from Apple's XNU osfmk/kern/cs_blobs.h.
enum {
    code_forced_library_validation = 0x00000010,
    code_restricted = 0x00000800,
    code_require_library_validation = 0x00002000,
    code_hardened_runtime = 0x00010000,
};

extern char **environ;

static bool entitlement(CFDictionaryRef entitlements, CFStringRef key)
{
    return entitlements && CFDictionaryGetValue(entitlements, key) == kCFBooleanTrue;
}

static bool signature_allows_injection(const char *target)
{
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL,
        (const UInt8 *)target, (CFIndex)strlen(target), false);
    if (!url) {
        return false;
    }
    SecStaticCodeRef code = NULL;
    OSStatus result = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    CFRelease(url);
    if (result != errSecSuccess) {
        return result == errSecCSUnsigned;
    }

    CFDictionaryRef info = NULL;
    result = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
    CFRelease(code);
    if (result != errSecSuccess) {
        return result == errSecCSUnsigned;
    }

    CFNumberRef flag_value = CFDictionaryGetValue(info, kSecCodeInfoFlags);
    int flags = 0;
    if (flag_value) {
        CFNumberGetValue(flag_value, kCFNumberIntType, &flags);
    }
    CFDictionaryRef entitlements = CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
    bool allowed = !CFDictionaryContainsKey(info, kSecCodeInfoPlatformIdentifier) &&
        !(flags & (code_restricted | code_forced_library_validation)) &&
        (!(flags & code_hardened_runtime) ||
            entitlement(entitlements, CFSTR("com.apple.security.cs.allow-dyld-environment-variables"))) &&
        (!(flags & (code_require_library_validation | code_hardened_runtime)) ||
            entitlement(entitlements, CFSTR("com.apple.security.cs.disable-library-validation")));
    CFRelease(info);
    return allowed;
}

static bool has_macho_magic(const char *target)
{
    int fd = open(target, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    uint32_t magic = 0;
    ssize_t bytes = read(fd, &magic, sizeof(magic));
    close(fd);
    return bytes == sizeof(magic) &&
        (magic == MH_MAGIC_64 || magic == FAT_MAGIC || magic == FAT_CIGAM ||
         magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64);
}

static bool asset_path(char *shim, size_t size, const char *name, bool allow_colon)
{
    char executable[PATH_MAX];
    uint32_t executable_size = sizeof(executable);
    char resolved[PATH_MAX];
    if (_NSGetExecutablePath(executable, &executable_size) != 0 ||
        !realpath(executable, resolved)) {
        return false;
    }
    *strrchr(resolved, '/') = '\0';
    int written = snprintf(shim, size, "%s/%s", resolved, name);
    struct stat status;
    return written >= 0 && (size_t)written < size &&
        (allow_colon || !strchr(shim, ':')) &&
        stat(shim, &status) == 0 && S_ISREG(status.st_mode);
}

static bool configure_bun(const char *preload, const char *native_library, int *preload_fd)
{
    *preload_fd = open(preload, O_RDONLY);
    if (*preload_fd < 0) {
        return false;
    }
    if (setenv("CLAUDE_WRAPPER_NATIVE_LIBRARY", native_library, 1) != 0 ||
        setenv("CLAUDE_WRAPPER_INIT_OWNER", "bun", 1) != 0) {
        close(*preload_fd);
        return false;
    }
    char preload_number[24];
    snprintf(preload_number, sizeof(preload_number), "%d", *preload_fd);
    if (setenv("CLAUDE_WRAPPER_PRELOAD_FD", preload_number, 1) != 0) {
        close(*preload_fd);
        return false;
    }
    const char *previous = getenv("BUN_OPTIONS");
    size_t previous_size = previous ? strlen(previous) : 0;
    size_t capacity = previous_size + 64;
    char *options = malloc(capacity);
    if (!options) {
        close(*preload_fd);
        return false;
    }
    size_t offset = 0;
    if (previous) {
        memcpy(options, previous, previous_size);
        offset = previous_size;
        options[offset++] = ' ';
        if (setenv("CLAUDE_WRAPPER_ORIGINAL_BUN_OPTIONS", previous, 1) != 0) {
            free(options);
            close(*preload_fd);
            return false;
        }
    } else {
        unsetenv("CLAUDE_WRAPPER_ORIGINAL_BUN_OPTIONS");
    }
    // BUN_OPTIONS in compiled clients does not accept shell-quoted paths.
    // An inherited descriptor also supports installation paths containing spaces.
    snprintf(options + offset, capacity - offset, "--preload /dev/fd/%d", *preload_fd);
    bool configured = setenv("BUN_OPTIONS", options, 1) == 0;
    free(options);
    unsetenv("DYLD_INSERT_LIBRARIES");
    if (!configured) {
        close(*preload_fd);
    }
    return configured;
}

static int prepare_pipe(int ready[2])
{
    if (pipe(ready) == -1) {
        return -1;
    }
    // Preserve the caller's descriptor layout even when stdio is closed.
    for (size_t i = 0; i < 2; i++) {
        if (ready[i] >= 3) {
            continue;
        }
        int moved = fcntl(ready[i], F_DUPFD, 3);
        if (moved == -1) {
            int saved_errno = errno;
            close(ready[0]);
            close(ready[1]);
            errno = saved_errno;
            return -1;
        }
        close(ready[i]);
        ready[i] = moved;
    }
    return 0;
}

static const int forward_signals[] = { SIGHUP, SIGINT, SIGQUIT, SIGTERM };
static volatile sig_atomic_t child_pid;
static bool group_supervised;

static void forward_signal(int signal, siginfo_t *info, void *context)
{
    (void)context;
    // Terminal-generated signals already go to the shared process group.
    if (child_pid && info->si_pid != 0 && !group_supervised) {
        int saved_errno = errno;
        kill(child_pid, signal);
        errno = saved_errno;
    }
}

static int spawn_target(const char *target, char **argv, int *ready, pid_t *child)
{
    posix_spawn_file_actions_t actions;
    int status = posix_spawn_file_actions_init(&actions);
    if (status != 0) {
        return status;
    }
    status = posix_spawn_file_actions_addclose(&actions, ready[0]);
    if (status != 0) {
        posix_spawn_file_actions_destroy(&actions);
        return status;
    }

    posix_spawnattr_t attributes;
    status = posix_spawnattr_init(&attributes);
    if (status != 0) {
        posix_spawn_file_actions_destroy(&actions);
        return status;
    }

    sigset_t block;
    sigemptyset(&block);
    for (size_t i = 0; i < sizeof(forward_signals) / sizeof(forward_signals[0]); i++) {
        sigaddset(&block, forward_signals[i]);
    }

    sigset_t original_mask;
    if (sigprocmask(SIG_BLOCK, &block, &original_mask) != 0) {
        status = errno;
    } else {
        struct sigaction action = { .sa_sigaction = forward_signal, .sa_mask = block,
                                    .sa_flags = SA_SIGINFO };
        for (size_t i = 0; i < sizeof(forward_signals) / sizeof(forward_signals[0]); i++) {
            struct sigaction previous;
            if (sigaction(forward_signals[i], NULL, &previous) != 0 ||
                (previous.sa_handler != SIG_IGN &&
                 sigaction(forward_signals[i], &action, NULL) != 0)) {
                status = errno;
                break;
            }
        }
        if (!status) {
            status = posix_spawnattr_setsigmask(&attributes, &original_mask);
        }
        if (!status) {
            status = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETSIGMASK);
        }
        if (!status) {
            status = posix_spawn(child, target, &actions, &attributes, argv, environ);
            if (!status) {
                child_pid = *child;
            }
        }
        sigprocmask(SIG_SETMASK, &original_mask, NULL);
    }
    posix_spawnattr_destroy(&attributes);
    posix_spawn_file_actions_destroy(&actions);
    return status;
}

static bool wait_for_shim(int fd)
{
    struct pollfd ready = { .fd = fd, .events = POLLIN };
    uint64_t deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) +
        (uint64_t)READY_TIMEOUT_MS * 1000000;
    for (;;) {
        uint64_t now = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
        if (now >= deadline) {
            return false;
        }
        int timeout = (int)((deadline - now + 999999) / 1000000);
        int status = poll(&ready, 1, timeout);
        if (status == -1 && errno == EINTR) {
            continue;
        }
        char marker;
        return status > 0 && (ready.revents & POLLIN) &&
            read(fd, &marker, 1) == 1 && marker == '1';
    }
}

int main(int argc, char **argv)
{
    bool bun = argc >= 2 &&
        (strcmp(argv[1], "--bun") == 0 || strcmp(argv[1], "--check-bun") == 0);
    bool check_only = argc >= 2 &&
        (strcmp(argv[1], "--check") == 0 || strcmp(argv[1], "--check-bun") == 0);
    int target_index = (check_only || bun) ? 2 : 1;
    const char *supervised = getenv("CLAUDE_WRAPPER_GROUP_SUPERVISED");
    group_supervised = supervised && strcmp(supervised, "1") == 0;
    unsetenv("CLAUDE_WRAPPER_GROUP_SUPERVISED");
    if (argc <= target_index || (check_only && argc != 3) || argv[target_index][0] != '/') {
        fputs("usage: identity-launch <absolute-Mach-O-target> [args...]\n"
              "       identity-launch --bun <absolute-Bun-target> [args...]\n"
              "       identity-launch --check[-bun] <absolute-Mach-O-target>\n", stderr);
        return 2;
    }
    char target[PATH_MAX];
    struct stat status;
    if (!realpath(argv[target_index], target) || stat(target, &status) != 0 ||
        !S_ISREG(status.st_mode) || access(target, X_OK) != 0 ||
        !has_macho_magic(target)) {
        fputs("identity-launch: target must be an executable Mach-O binary\n", stderr);
        return 126;
    }
    if ((status.st_mode & (S_ISUID | S_ISGID)) || (status.st_flags & SF_RESTRICTED) ||
        (!bun && !signature_allows_injection(target))) {
        fputs("identity-launch: target signing or system policy prevents native injection\n",
              stderr);
        return 126;
    }
    char shim[PATH_MAX];
    const char *asset = bun ? "identity.cjs" : SHIM_NAME;
    if (!asset_path(shim, sizeof(shim), asset, bun)) {
        fprintf(stderr, "identity-launch: cannot locate adjacent %s\n", asset);
        return 126;
    }
    char native_library[PATH_MAX] = "";
    if (bun && !asset_path(native_library, sizeof(native_library), SHIM_NAME, true)) {
        fprintf(stderr, "identity-launch: cannot locate adjacent %s\n", SHIM_NAME);
        return 126;
    }
    if (check_only) {
        return 0;
    }

    int ready[2];
    if (prepare_pipe(ready) != 0) {
        perror("identity-launch: create readiness pipe");
        return 126;
    }
    char write_fd[16];
    int preload_fd = -1;
    snprintf(write_fd, sizeof(write_fd), "%d", ready[1]);
    if (setenv(READY_FD, write_fd, 1) != 0 ||
        (bun ? !configure_bun(shim, native_library, &preload_fd) : setenv("DYLD_INSERT_LIBRARIES", shim, 1) != 0)) {
        perror("identity-launch: configure injection");
        return 126;
    }

    pid_t child;
    int spawn_status = spawn_target(target, argv + target_index, ready, &child);
    if (preload_fd >= 0) {
        close(preload_fd);
    }
    close(ready[1]);
    if (spawn_status != 0) {
        fprintf(stderr, "identity-launch: could not launch target: %s\n", strerror(spawn_status));
        return 126;
    }
    bool loaded = wait_for_shim(ready[0]);
    close(ready[0]);
    if (!loaded) {
        fputs("identity-launch: target did not confirm identity initialization\n", stderr);
        kill(child, SIGKILL);
    }
    // Keep the exited child unreaped until signals can no longer be forwarded to its PID.
    siginfo_t exit_info;
    int wait_status;
    do {
        wait_status = waitid(P_PID, (id_t)child, &exit_info, WEXITED | WNOWAIT);
    } while (wait_status == -1 && errno == EINTR);
    child_pid = 0;
    if (wait_status == -1) {
        perror("identity-launch: wait for target");
        return 126;
    }
    while (waitpid(child, NULL, 0) == -1 && errno == EINTR) {
    }
    if (!loaded) {
        return 126;
    }
    return exit_info.si_code == CLD_EXITED ? exit_info.si_status : 128 + exit_info.si_status;
}
