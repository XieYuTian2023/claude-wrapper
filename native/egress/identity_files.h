#ifndef CW_IDENTITY_FILES_H
#define CW_IDENTITY_FILES_H
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct cw_rules { char *bytes; size_t used; size_t capacity; };

static bool cw_no_identity_symlink(const char *path) {
    struct stat info;
    if (lstat(path, &info) == 0 && S_ISLNK(info.st_mode)) {
        errno = ELOOP;
        return false;
    }
    return true;
}

static bool cw_append(struct cw_rules *out, const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(out->bytes + out->used, out->capacity - out->used, format, arguments);
    va_end(arguments);
    if (length < 0 || (size_t)length >= out->capacity - out->used) {
        errno = E2BIG;
        return false;
    }
    out->used += (size_t)length;
    return true;
}

static bool cw_quote_path(struct cw_rules *out, const char *path) {
    if (!path || path[0] != '/' || !cw_append(out, "\"")) { errno = EINVAL; return false; }
    for (const unsigned char *byte = (const void *)path; *byte; byte++) {
        if (*byte < 32 || *byte == 127) { errno = EINVAL; return false; }
        if ((*byte == '\\' || *byte == '"') && !cw_append(out, "\\")) return false;
        if (!cw_append(out, "%c", *byte)) return false;
    }
    return cw_append(out, "\"");
}

static bool cw_file_rule(struct cw_rules *out, const char *operation, const char *path) {
    return cw_append(out, "(deny %s (literal ", operation) && cw_quote_path(out, path) && cw_append(out, "))");
}

// Resolve parent aliases, but never follow the final localtime symlink into
// public zoneinfo. Denying that shared target would also break the US timezone.
static bool cw_identity_path(struct cw_rules *out, const char *path, bool localtime_alias) {
    if (!localtime_alias && !cw_no_identity_symlink(path)) {
        // A preference symlink may point into an ordinary project. Do not deny
        // that project file's canonical vnode as an accidental side effect.
        errno = ELOOP;
        return false;
    }
    if (!cw_file_rule(out, "file-read*", path) || !cw_file_rule(out, "file-write*", path)) return false;
    char parent[PATH_MAX], canonical[PATH_MAX], normalized[PATH_MAX];
    if (strlcpy(parent, path, sizeof(parent)) >= sizeof(parent)) { errno = ENAMETOOLONG; return false; }
    char *basename = strrchr(parent, '/');
    if (!basename || basename == parent) return true;
    *basename++ = '\0';
    if (realpath(parent, canonical)) {
        int length = snprintf(normalized, sizeof(normalized), "%s/%s", canonical, basename);
        if (length < 0 || (size_t)length >= sizeof(normalized)) { errno = ENAMETOOLONG; return false; }
        if (strcmp(normalized, path) &&
            (!cw_file_rule(out, "file-read*", normalized) || !cw_file_rule(out, "file-write*", normalized))) return false;
    }
    return true;
}

static bool cw_preference_root(struct cw_rules *out, const char *root) {
    // A preference directory redirected into a project must not turn that
    // project's canonical files or directory enumeration into identity sources.
    if (!cw_no_identity_symlink(root)) return false;
    const char *names[] = { ".GlobalPreferences.plist", ".GlobalPreferences_m.plist" };
    char path[PATH_MAX];
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        int length = snprintf(path, sizeof(path), "%s/%s", root, names[i]);
        if (length < 0 || (size_t)length >= sizeof(path) || !cw_identity_path(out, path, false)) return false;
    }
    int length = snprintf(path, sizeof(path), "%s/ByHost", root);
    if (length < 0 || (size_t)length >= sizeof(path)) { errno = ENAMETOOLONG; return false; }
    if (!cw_no_identity_symlink(path)) return false;
    char canonical[PATH_MAX];
    const char *directory = realpath(path, canonical) ? canonical : path;
    // Names in this system namespace embed the physical host UUID. This rule
    // denies directory enumeration, not all reads below the directory.
    if (!cw_file_rule(out, "file-read-data", directory)) return false;
    DIR *entries = opendir(directory);
    if (!entries) return errno == ENOENT || errno == ENOTDIR;
    size_t matched = 0;
    bool success = true;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(entries);
        if (!entry) { if (errno) success = false; break; }
        const char *name = entry->d_name;
        size_t size = strlen(name);
        if (strncmp(name, ".GlobalPreferences.", 19) || size < 25 || strcmp(name + size - 6, ".plist")) continue;
        if (++matched > 128) { errno = E2BIG; success = false; break; }
        char identity[PATH_MAX];
        int count = snprintf(identity, sizeof(identity), "%s/%s", directory, name);
        if (count < 0 || (size_t)count >= sizeof(identity) || !cw_identity_path(out, identity, false)) { success = false; break; }
    }
    int error = errno;
    if (closedir(entries) == -1) { error = errno; success = false; }
    errno = error;
    return success;
}

static bool cw_home_preferences(struct cw_rules *out, const char *home) {
    if (!home || !*home) return true;
    char canonical[PATH_MAX], library[PATH_MAX], root[PATH_MAX], encoding[PATH_MAX];
    const char *base = realpath(home, canonical) ? canonical : home;
    if (base[0] != '/') { errno = EINVAL; return false; }
    int a = snprintf(root, sizeof(root), "%s/Library/Preferences", base);
    int b = snprintf(encoding, sizeof(encoding), "%s/.CFUserTextEncoding", base);
    int c = snprintf(library, sizeof(library), "%s/Library", base);
    if (a < 0 || b < 0 || c < 0 || (size_t)a >= sizeof(root) || (size_t)b >= sizeof(encoding) ||
        (size_t)c >= sizeof(library)) { errno = ENAMETOOLONG; return false; }
    if (!cw_no_identity_symlink(library)) return false;
    return cw_preference_root(out, root) && cw_identity_path(out, encoding, false);
}

static bool cw_identity_file_rules(struct cw_rules *out) {
    const char *home = getenv("CLAUDE_WRAPPER_ACCOUNT_HOME");
    if (!home) {
        struct passwd *account = getpwuid(getuid());
        if (!account || !account->pw_dir) { errno = ENOENT; return false; }
        home = account->pw_dir;
    }
    // libc's account buffer can be overwritten by later account operations.
    char account_home[PATH_MAX];
    if (strlcpy(account_home, home, sizeof(account_home)) >= sizeof(account_home)) { errno = ENAMETOOLONG; return false; }
    if (!cw_append(out,
        "(deny mach-lookup (global-name \"com.apple.SystemConfiguration.configd\" \"com.apple.cfprefsd.daemon\"))"
        "(deny user-preference-read (preference-domain \"SystemConfiguration\" \".GlobalPreferences\"))")) return false;
    if (!cw_no_identity_symlink("/Library") ||
        !cw_no_identity_symlink("/Library/Preferences") ||
        !cw_no_identity_symlink("/Library/Preferences/SystemConfiguration")) return false;
    const char *system_sources[] = {
        "/Library/Preferences/SystemConfiguration/preferences.plist",
        "/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist",
        "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist",
        "/Library/Preferences/SystemConfiguration/com.apple.smb.server.plist",
        "/Library/Preferences/SystemConfiguration/com.apple.network.identification.plist",
        "/Library/Preferences/com.apple.wifi.known-networks.plist",
        "/Library/Preferences/com.apple.timezone.auto.plist",
        "/Library/Preferences/com.apple.locationd.plist",
    };
    for (size_t i = 0; i < sizeof(system_sources) / sizeof(system_sources[0]); i++)
        if (!cw_identity_path(out, system_sources[i], false)) return false;
    if (!cw_preference_root(out, "/Library/Preferences") || !cw_home_preferences(out, account_home)) return false;
    const char *caller_home = getenv("HOME");
    if (caller_home && strcmp(caller_home, account_home) && !cw_home_preferences(out, caller_home)) return false;
    // The system resolver alias is intentionally not followed. The actual
    // backing file is independently covered, while public DNS data is allowed.
    const char *resolver_sources[] = { "/etc/resolv.conf", "/private/etc/resolv.conf",
        "/var/run/resolv.conf", "/private/var/run/resolv.conf" };
    for (size_t i = 0; i < sizeof(resolver_sources) / sizeof(resolver_sources[0]); i++)
        if (!cw_identity_path(out, resolver_sources[i], true)) return false;
    return cw_identity_path(out, "/private/etc/localtime", true) &&
        cw_identity_path(out, "/etc/localtime", true) &&
        cw_identity_path(out, "/var/db/timezone/localtime", true);
}
#endif
