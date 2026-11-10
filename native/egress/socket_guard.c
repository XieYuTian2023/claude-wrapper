#include <dirent.h>
#include <errno.h>
#include <sandbox.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "identity_files.h"
#include "../diagnostics.h"

static int check_inherited_descriptors(void) {
    for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
        struct stat info;
        if (fstat(fd, &info) == -1) {
            if (errno != EBADF) return -1;
        } else if (S_ISSOCK(info.st_mode)) {
            errno = EPERM;
            return -1;
        }
    }

    // An already-open socket would avoid the policy's connect check.
    DIR *descriptors = opendir("/dev/fd");
    if (descriptors == NULL) return -1;
    int listing_fd = dirfd(descriptors);
    int error = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(descriptors);
        if (entry == NULL) {
            error = errno;
            break;
        }
        char *end;
        long fd = strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0' || fd <= STDERR_FILENO || fd == listing_fd) {
            continue;
        }
        struct stat info;
        if (fstat((int)fd, &info) == -1) {
            if (errno == EBADF) continue;
            error = errno;
            break;
        }
        // Preserve inherited files, directories, terminals, and pipes verbatim.
        if (S_ISSOCK(info.st_mode) && close((int)fd) == -1 && errno != EBADF) {
            error = errno;
            break;
        }
    }
    if (closedir(descriptors) == -1 && error == 0) error = errno;
    errno = error;
    return error == 0 ? 0 : -1;
}

int main(int argc, char **argv) {
    int port_index = 1;
    const char *protocol = "tcp";
    if (argc > 1 && strcmp(argv[1], "--ipv4") == 0) {
        protocol = "tcp4";
        port_index++;
    } else if (argc > 1 && strcmp(argv[1], "--ipv6") == 0) {
        protocol = "tcp6";
        port_index++;
    }
    const char *interface_rules = "";
    const char *account_rules = "";
    bool identity_files = false;
    char identity_rules[4096] = "";
    while (argc > port_index) {
        if (strcmp(argv[port_index], "--hide-interfaces") == 0) {
            interface_rules = "(deny sysctl-read (sysctl-name-prefix \"net.route\"))"
                              "(deny system-socket (socket-domain AF_ROUTE))";
        } else if (strcmp(argv[port_index], "--identity-guard") == 0) {
            int written = snprintf(identity_rules, sizeof identity_rules,
                "(deny syscall-unix (syscall-number %d))"
                "(deny sysctl-read (sysctl-name-prefix \"kern.uuid\"))"
                "(deny sysctl-read (sysctl-name-prefix \"kern.bootsessionuuid\"))"
                "(deny iokit-get-properties (iokit-property"
                " \"IOPlatformUUID\" \"IOPlatformSerialNumber\" \"IOMACAddress\""
                " \"IO80211BSSID\" \"IO80211SSID\" \"IO80211CountryCode\" \"CountryCode\""
                " \"DisplaySerialNumber\" \"FirmwareSerialNumber\" \"Serial\" \"Serial Number\" \"SerialNumber\""
                " \"ThunderboltUUID\" \"USB Serial Number\" \"kUSBSerialNumberString\" \"serial-number\""
                " \"UUID\" \"NamespaceUUID\" \"VolGroupUUID\" \"boot-uuid-media\" \"previous-system-uuid\""
                " \"Domain UUID\" \"BootSessionUUID\" \"SleepWakeUUID\" \"IOSkywalkNexusUUID\""
                " \"IODisplayEDID\" \"prev-lang:kbd\"))"
                "(deny nvram-get nvram-set (nvram-variable \"prev-lang:kbd\" \"previous-system-uuid\"))"
                "(deny mach-lookup (global-name"
                " \"com.apple.locationd.desktop.agent\" \"com.apple.locationd.desktop.registration\""
                " \"com.apple.locationd.desktop.spi\" \"com.apple.locationd.desktop.synchronous\""
                " \"com.apple.locationd.routine\" \"com.apple.locationd.simulation\""
                " \"com.apple.airportd\" \"com.apple.corewlan-xpc\" \"com.apple.private.corewifi-xpc\""
                " \"com.apple.private.corewifi.internal-xpc\" \"com.apple.private.corewifi.readonly-xpc\""
                " \"com.apple.private.corewifi.unrestricted-xpc\" \"com.apple.wifi-xpc\""
                " \"com.apple.wifi.sharekit\" \"com.apple.wifi.useragent\"))",
                SYS_gethostuuid);
            if (written < 0 || (size_t)written >= sizeof identity_rules) return 125;
        } else if (strcmp(argv[port_index], "--hide-account-records") == 0) {
            account_rules = "(deny mach-lookup (global-name \"com.apple.system.opendirectoryd.api\""
                            " \"com.apple.system.opendirectoryd.libinfo\""
                            " \"com.apple.system.opendirectoryd.membership\"))";
        } else if (strcmp(argv[port_index], "--identity-files") == 0) {
            identity_files = true;
        } else {
            break;
        }
        port_index++;
    }
    if (argc <= port_index + 1 || argv[port_index + 1][0] != '/' || strlen(argv[port_index]) > 5 ||
        strspn(argv[port_index], "0123456789") != strlen(argv[port_index])) {
        fputs("usage: socket-guard [--ipv4 | --ipv6] [--hide-interfaces] [--identity-guard] [--hide-account-records] [--identity-files] PORT /absolute/target [args...]\n",
              stderr);
        return 125;
    }
    unsigned long port = strtoul(argv[port_index], NULL, 10);
    if (port == 0 || port > 65535) {
        cw_error("expected a port from 1 to 65535");
        return 125;
    }
    if (check_inherited_descriptors() == -1) {
        cw_error("unsafe inherited descriptors: %s", strerror(errno));
        return 125;
    }

    char profile[65536];
    int length = snprintf(profile, sizeof profile,
        "(version 1) (allow default)"
        "(deny network*)"
        "(allow network-outbound (remote %s \"localhost:%lu\"))"
        "(deny mach-lookup (global-name \"com.apple.dnssd.service\""
        " \"com.apple.nsurlsessiond\" \"com.apple.lsd.open\" \"com.apple.lsd.openurl\"))"
        "(deny appleevent-send)%s%s%s", protocol, port, interface_rules, identity_rules, account_rules);
    if (length < 0 || (size_t)length >= sizeof profile) {
        cw_error("could not construct network policy");
        return 125;
    }
    struct cw_rules rules = { .bytes = profile, .used = (size_t)length, .capacity = sizeof(profile) };
    if (identity_files && !cw_identity_file_rules(&rules)) {
        cw_error("could not prepare system identity sources: %s", strerror(errno));
        return 125;
    }

    char *error = NULL;
    // Literal profiles use flags=0, as in Apple's sandbox-exec.
    if (sandbox_init(profile, 0, &error) != 0) {
        cw_error("could not apply network policy: %s", error == NULL ? "unknown error" : error);
        if (error != NULL) sandbox_free_error(error);
        return 125;
    }
    char **target = argv + port_index + 1;
    execv(*target, target);
    cw_error("could not start the guarded client: %s", strerror(errno));
    return 126;
}
