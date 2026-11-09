#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <IOKit/IOKitLib.h>
#import <SystemConfiguration/SystemConfiguration.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <servers/bootstrap.h>
#include <dirent.h>

// This diagnostic emits only availability, keyed digests and comparisons.
// The Python controller supplies a one-run random digest key and removes the
// digests from its public output. Never print the queried identity values.
static NSString *string(const char *value);
static NSString *digest(NSData *bytes, NSData *key) {
    if (!bytes) return nil;
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    CC_SHA256_Update(&context, key.bytes, (CC_LONG)key.length);
    CC_SHA256_Update(&context, bytes.bytes, (CC_LONG)bytes.length);
    unsigned char output[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(output, &context);
    NSMutableString *hex = [NSMutableString string];
    for (size_t i = 0; i < sizeof(output); i++) [hex appendFormat:@"%02x", output[i]];
    return hex;
}

static NSDictionary *result(NSString *value, int error, NSString *wanted, NSData *key) {
    NSMutableDictionary *record = [@{@"available": @(value != nil), @"nonempty": @(value.length > 0), @"errno": @(error)} mutableCopy];
    if (value) record[@"digest"] = digest([value dataUsingEncoding:NSUTF8StringEncoding], key);
    if (wanted && value) record[@"matches_requested"] = @([value isEqualToString:wanted]);
    return record;
}

static NSDictionary *bytes_result(NSData *value, int error, NSData *key) {
    NSMutableDictionary *record = [@{@"available": @(value != nil), @"nonempty": @(value.length > 0), @"errno": @(error)} mutableCopy];
    if (value) record[@"digest"] = digest(value, key);
    return record;
}

static NSDictionary *read_source_file(const char *path, NSData *key) {
    errno = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return bytes_result(nil, errno, key);
    unsigned char buffer[256];
    ssize_t count = read(fd, buffer, sizeof(buffer));
    int error = errno;
    close(fd);
    return bytes_result(count >= 0 ? [NSData dataWithBytes:buffer length:(NSUInteger)count] : nil, count >= 0 ? 0 : error, key);
}

static NSDictionary *source_write_capability(const char *path, NSData *key) {
    // Open without O_TRUNC/O_CREAT and close immediately: no source data is written.
    errno = 0;
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    int error = errno;
    if (fd >= 0) close(fd);
    return result(fd >= 0 ? @"writable-handle-only" : nil, fd >= 0 ? 0 : error, nil, key);
}

static NSDictionary *enumerate_identity_directory(NSString *path, NSString *expectedUUIDDigest, NSData *key) {
    DIR *directory = opendir(path.fileSystemRepresentation);
    if (!directory) return @{@"available": @NO, @"errno": @(errno)};
    NSRegularExpression *uuid_pattern = [NSRegularExpression regularExpressionWithPattern:@"[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}" options:0 error:nil];
    NSUInteger uuid_count = 0;
    NSUInteger host_uuid_count = 0;
    int error = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { error = errno; break; }
        NSString *filename = string(entry->d_name);
        if (!filename) continue;
        for (NSTextCheckingResult *match in [uuid_pattern matchesInString:filename options:0 range:NSMakeRange(0, filename.length)]) {
            uuid_count++;
            NSString *uuid = [[filename substringWithRange:match.range] lowercaseString];
            if (expectedUUIDDigest && [digest([uuid dataUsingEncoding:NSUTF8StringEncoding], key) isEqualToString:expectedUUIDDigest]) host_uuid_count++;
        }
    }
    closedir(directory);
    return @{@"available": @(error == 0), @"errno": @(error), @"filename_uuid_count": @(uuid_count), @"matches_baseline_host_uuid_count": @(host_uuid_count), @"host_uuid_comparison_available": @(expectedUUIDDigest != nil)};
}

static NSDictionary *replica_write_operations(const char *path) {
    NSMutableDictionary *operations = [NSMutableDictionary dictionary];
    errno = 0;
    int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    operations[@"open_truncate"] = @{@"available": @(fd >= 0), @"errno": @(fd >= 0 ? 0 : errno)};
    if (fd >= 0) close(fd);
    errno = 0;
    int changed_mode = chmod(path, 0640);
    operations[@"chmod"] = @{@"available": @(changed_mode == 0), @"errno": @(changed_mode == 0 ? 0 : errno)};
    NSString *replacement = [string(path) stringByAppendingString:@".replacement"];
    fd = open(replacement.fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0) {
        (void)write(fd, "replica replacement", 19);
        close(fd);
    }
    errno = 0;
    int replaced = rename(replacement.fileSystemRepresentation, path);
    operations[@"atomic_replace"] = @{@"available": @(replaced == 0), @"errno": @(replaced == 0 ? 0 : errno)};
    if (replaced != 0) unlink(replacement.fileSystemRepresentation);
    errno = 0;
    int removed = unlink(path);
    operations[@"unlink"] = @{@"available": @(removed == 0), @"errno": @(removed == 0 ? 0 : errno)};
    return operations;
}

static NSString *string(const char *value) {
    return value ? [NSString stringWithUTF8String:value] : nil;
}

static NSDictionary *sysctl_string(const char *name, NSString *wanted, NSData *key) {
    char bytes[4096] = {0};
    size_t size = sizeof(bytes) - 1;
    errno = 0;
    int code = sysctlbyname(name, bytes, &size, NULL, 0);
    return result(code == 0 ? string(bytes) : nil, code == 0 ? 0 : errno, wanted, key);
}

static NSString *description(CFTypeRef value) {
    return value ? [(__bridge id)value description] : nil;
}

static NSDictionary *lookup_service(const char *name, NSData *key) {
    mach_port_t service = MACH_PORT_NULL;
    kern_return_t code = bootstrap_look_up(bootstrap_port, name, &service);
    NSDictionary *record = result(code == KERN_SUCCESS ? @"service-port" : nil, (int)code, nil, key);
    if (service != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), service);
    return record;
}

static NSDictionary *name_result(CFStringRef value, int error, NSString *wanted, NSData *key) {
    NSMutableDictionary *record = [result((__bridge NSString *)value, error, wanted, key) mutableCopy];
    record[@"generic_fallback"] = @(value && [@[@"localhost", @"localhost.local", @"Macintosh", @"macintosh", @"Computer", @"computer", @"Mac", @"mac", @"Mac.local", @"Device", @"device", @"Unknown", @"unknown", @"unknown-host", @"Unknown Host", @"<unknown>", @"Restricted", @"restricted", @"redacted", @"Private", @"private"] containsObject:(__bridge NSString *)value]);
    return record;
}

static NSDictionary *classified_name_result(CFStringRef value, int error, NSString *wanted, NSString *nativeUser, NSString *nativeFullUser, NSData *key) {
    NSMutableDictionary *record = [name_result(value, error, wanted, key) mutableCopy];
    NSString *name = (__bridge NSString *)value;
    record[@"contains_native_short_name"] = @(name && nativeUser.length > 0 && [name rangeOfString:nativeUser options:NSCaseInsensitiveSearch].location != NSNotFound);
    record[@"contains_native_full_name"] = @(name && nativeFullUser.length > 0 && [name rangeOfString:nativeFullUser options:NSCaseInsensitiveSearch].location != NSNotFound);
    record[@"contains_requested_user"] = @(name && [name rangeOfString:@"identity-probe-user" options:NSCaseInsensitiveSearch].location != NSNotFound);
    return record;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if ((argc != 2 && argc != 3) || !getenv("IDENTITY_PROBE_DIGEST_KEY")) return 2;
        NSData *key = [string(getenv("IDENTITY_PROBE_DIGEST_KEY")) dataUsingEncoding:NSUTF8StringEncoding];
        NSString *wantedHost = @"identity-probe-host";
        NSString *wantedUser = @"identity-probe-user";
        NSString *wantedZone = @"America/Los_Angeles";
        NSMutableDictionary *output = [NSMutableDictionary dictionary];

        char hostname[1024] = {0};
        errno = 0;
        int host_code = gethostname(hostname, sizeof(hostname) - 1);
        output[@"gethostname"] = result(host_code == 0 ? string(hostname) : nil, host_code == 0 ? 0 : errno, wantedHost, key);
        output[@"sysctl_hostname"] = sysctl_string("kern.hostname", wantedHost, key);
        output[@"sysctl_hw_model"] = sysctl_string("hw.model", nil, key);
        output[@"sysctl_kern_uuid"] = sysctl_string("kern.uuid", nil, key);
        uuid_t host_uuid = {0};
        struct timespec uuid_wait = {.tv_sec = 1, .tv_nsec = 0};
        errno = 0;
        int uuid_code = gethostuuid(host_uuid, &uuid_wait);
        int uuid_error = errno;
        char uuid_text[37] = {0};
        if (uuid_code == 0) uuid_unparse_lower(host_uuid, uuid_text);
        output[@"gethostuuid"] = result(uuid_code == 0 ? string(uuid_text) : nil, uuid_code == 0 ? 0 : uuid_error, nil, key);

        struct utsname name = {0};
        errno = 0;
        int uname_code = uname(&name);
        int uname_error = errno;
        output[@"uname_nodename"] = result(uname_code == 0 ? string(name.nodename) : nil, uname_code == 0 ? 0 : uname_error, wantedHost, key);
        output[@"uname_sysname"] = result(uname_code == 0 ? string(name.sysname) : nil, uname_code == 0 ? 0 : uname_error, nil, key);

        errno = 0;
        char *login = getlogin();
        output[@"getlogin"] = result(string(login), login ? 0 : errno, wantedUser, key);
        errno = 0;
        struct passwd *user = getpwuid(getuid());
        NSString *nativeUser = user ? string(user->pw_name) : nil;
        int user_error = errno;
        output[@"getpwuid_name"] = result(user ? string(user->pw_name) : nil, user ? 0 : user_error, wantedUser, key);
        output[@"getpwuid_home"] = result(user ? string(user->pw_dir) : nil, user ? 0 : user_error, nil, key);
        struct passwd user_record = {0};
        struct passwd *reentrant_user = NULL;
        char passwd_buffer[16384];
        int passwd_code = getpwuid_r(getuid(), &user_record, passwd_buffer, sizeof(passwd_buffer), &reentrant_user);
        output[@"getpwuid_r_name"] = result(reentrant_user ? string(reentrant_user->pw_name) : nil, passwd_code, wantedUser, key);
        output[@"getpwuid_r_home"] = result(reentrant_user ? string(reentrant_user->pw_dir) : nil, passwd_code, nil, key);
        output[@"uid"] = result([NSString stringWithFormat:@"%u", getuid()], 0, nil, key);
        output[@"NSUserName"] = result(NSUserName(), 0, wantedUser, key);
        NSString *nativeFullUser = NSFullUserName();
        output[@"NSFullUserName"] = result(nativeFullUser, 0, wantedUser, key);
        output[@"NSHomeDirectory"] = result(NSHomeDirectory(), 0, nil, key);
        output[@"getenv_USER"] = result(string(getenv("USER")), 0, wantedUser, key);
        output[@"getenv_HOSTNAME"] = result(string(getenv("HOSTNAME")), 0, wantedHost, key);

        output[@"bootstrap_configd"] = lookup_service("com.apple.SystemConfiguration.configd", key);
        output[@"bootstrap_configd_helper"] = lookup_service("com.apple.SystemConfiguration.helper", key);
        output[@"bootstrap_opendirectory_libinfo"] = lookup_service("com.apple.system.opendirectoryd.libinfo", key);
        output[@"bootstrap_cfprefsd_agent"] = lookup_service("com.apple.cfprefsd.agent", key);
        output[@"bootstrap_cfprefsd_daemon"] = lookup_service("com.apple.cfprefsd.daemon", key);

        CFStringEncoding computer_encoding = 0;
        CFStringRef computer_name = SCDynamicStoreCopyComputerName(NULL, &computer_encoding);
        output[@"SCDynamicStore_computer_name"] = classified_name_result(computer_name, computer_name ? 0 : SCError(), wantedHost, nativeUser, nativeFullUser, key);
        if (computer_name) CFRelease(computer_name);
        CFStringRef local_hostname = SCDynamicStoreCopyLocalHostName(NULL);
        output[@"SCDynamicStore_local_hostname"] = classified_name_result(local_hostname, local_hostname ? 0 : SCError(), wantedHost, nativeUser, nativeFullUser, key);
        if (local_hostname) CFRelease(local_hostname);
        SCPreferencesRef system_preferences = SCPreferencesCreate(kCFAllocatorDefault, CFSTR("IdentitySourceProbe"), NULL);
        CFDictionaryRef system_dictionary = system_preferences ? SCPreferencesPathGetValue(system_preferences, CFSTR("/System/System")) : NULL;
        CFStringRef preferences_computer_name = system_dictionary && CFGetTypeID(system_dictionary) == CFDictionaryGetTypeID()
            ? CFDictionaryGetValue(system_dictionary, kSCPropSystemComputerName) : NULL;
        NSMutableDictionary *preferences_name_record = [result((__bridge NSString *)preferences_computer_name, preferences_computer_name ? 0 : SCError(), wantedHost, key) mutableCopy];
        preferences_name_record[@"same_as_dynamic_store"] = @([preferences_name_record[@"digest"] isEqual:output[@"SCDynamicStore_computer_name"][@"digest"]]);
        output[@"SCPreferences_computer_name"] = preferences_name_record;
        CFDictionaryRef preferences_hostnames = system_preferences ? SCPreferencesPathGetValue(system_preferences, CFSTR("/System/Network/HostNames")) : NULL;
        CFStringRef preferences_local_hostname = preferences_hostnames && CFGetTypeID(preferences_hostnames) == CFDictionaryGetTypeID()
            ? CFDictionaryGetValue(preferences_hostnames, kSCPropNetLocalHostName) : NULL;
        NSMutableDictionary *preferences_hostname_record = [result((__bridge NSString *)preferences_local_hostname, preferences_local_hostname ? 0 : SCError(), wantedHost, key) mutableCopy];
        preferences_hostname_record[@"same_as_dynamic_store"] = @([preferences_hostname_record[@"digest"] isEqual:output[@"SCDynamicStore_local_hostname"][@"digest"]]);
        output[@"SCPreferences_local_hostname"] = preferences_hostname_record;
        if (system_preferences) CFRelease(system_preferences);

        CFTimeZoneRef system_zone = CFTimeZoneCopySystem();
        CFTimeZoneRef default_zone = CFTimeZoneCopyDefault();
        NSMutableDictionary *system_timezone_record = [result(system_zone ? (__bridge NSString *)CFTimeZoneGetName(system_zone) : nil, 0, wantedZone, key) mutableCopy];
        system_timezone_record[@"generic_utc"] = @(system_zone && [@[@"GMT", @"UTC", @"Etc/UTC", @"Etc/GMT"] containsObject:(__bridge NSString *)CFTimeZoneGetName(system_zone)]);
        output[@"CFTimeZone_system"] = system_timezone_record;
        output[@"CFTimeZone_default"] = result(default_zone ? (__bridge NSString *)CFTimeZoneGetName(default_zone) : nil, 0, wantedZone, key);
        if (system_zone) CFRelease(system_zone);
        if (default_zone) CFRelease(default_zone);
        output[@"NSTimeZone_system"] = result(NSTimeZone.systemTimeZone.name, 0, wantedZone, key);
        char localtime_link[4096] = {0};
        errno = 0;
        ssize_t link_size = readlink("/etc/localtime", localtime_link, sizeof(localtime_link) - 1);
        output[@"localtime_symlink"] = result(link_size >= 0 ? string(localtime_link) : nil, link_size >= 0 ? 0 : errno, nil, key);
        output[@"localtime_source_data"] = read_source_file("/etc/localtime", key);
        output[@"profile_zoneinfo_data"] = read_source_file("/usr/share/zoneinfo/America/Los_Angeles", key);
        time_t now = time(NULL);
        struct tm local = {0};
        tzset();
        struct tm *local_result = localtime_r(&now, &local);
        output[@"localtime_zone"] = result(local_result ? string(local.tm_zone) : nil, local_result ? 0 : errno, nil, key);
        NSString *wanted_offset = [NSString stringWithFormat:@"%ld", (long)[[NSTimeZone timeZoneWithName:wantedZone] secondsFromGMTForDate:[NSDate date]]];
        output[@"localtime_offset"] = result(local_result ? [NSString stringWithFormat:@"%ld", local.tm_gmtoff] : nil, local_result ? 0 : errno, wanted_offset, key);

        CFLocaleRef locale = CFLocaleCopyCurrent();
        NSMutableDictionary *locale_record = [result(locale ? (__bridge NSString *)CFLocaleGetIdentifier(locale) : nil, 0, @"en_US", key) mutableCopy];
        CFStringRef country = locale ? CFLocaleGetValue(locale, kCFLocaleCountryCode) : NULL;
        CFStringRef language = locale ? CFLocaleGetValue(locale, kCFLocaleLanguageCode) : NULL;
        locale_record[@"has_region"] = @(country && CFStringGetLength(country) > 0);
        locale_record[@"matches_requested_region"] = @([(__bridge NSString *)country isEqualToString:@"US"]);
        locale_record[@"matches_requested_language"] = @([(__bridge NSString *)language isEqualToString:@"en"]);
        if (country) locale_record[@"country_digest"] = digest([(__bridge NSString *)country dataUsingEncoding:NSUTF8StringEncoding], key);
        if (language) locale_record[@"language_digest"] = digest([(__bridge NSString *)language dataUsingEncoding:NSUTF8StringEncoding], key);
        output[@"CFLocale_current"] = locale_record;
        if (locale) CFRelease(locale);
        CFArrayRef languages = CFLocaleCopyPreferredLanguages();
        output[@"CFLocale_languages"] = result(description(languages), 0, nil, key);
        output[@"CFLocale_first_language"] = result(languages && CFArrayGetCount(languages) > 0 ? (__bridge NSString *)CFArrayGetValueAtIndex(languages, 0) : nil, 0, @"en-US", key);
        if (languages) CFRelease(languages);
        CFPropertyListRef apple_locale = CFPreferencesCopyValue(CFSTR("AppleLocale"), kCFPreferencesAnyApplication, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
        output[@"CFPreferences_AppleLocale"] = result(description(apple_locale), 0, @"en_US", key);
        if (apple_locale) CFRelease(apple_locale);

        const char *source_json = getenv("IDENTITY_PROBE_SOURCE_PATHS");
        if (source_json) {
            NSData *source_data = [string(source_json) dataUsingEncoding:NSUTF8StringEncoding];
            NSDictionary *sources = [NSJSONSerialization JSONObjectWithData:source_data options:0 error:nil];
            for (NSString *label in sources) {
                output[[@"file_source_" stringByAppendingString:label]] = read_source_file([sources[label] fileSystemRepresentation], key);
                output[[@"write_handle_" stringByAppendingString:label]] = source_write_capability([sources[label] fileSystemRepresentation], key);
            }
        }
        const char *directory_json = getenv("IDENTITY_PROBE_BYHOST_DIRECTORIES");
        if (directory_json) {
            NSDictionary *directories = [NSJSONSerialization JSONObjectWithData:[string(directory_json) dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
            NSString *uuid_digest = string(getenv("IDENTITY_PROBE_BASELINE_UUID_DIGEST")) ?: output[@"gethostuuid"][@"digest"];
            for (NSString *label in directories) output[[@"directory_source_" stringByAppendingString:label]] = enumerate_identity_directory(directories[label], uuid_digest, key);
        }
        const char *sample_json = getenv("IDENTITY_PROBE_BYHOST_SAMPLES");
        if (sample_json) {
            NSDictionary *samples = [NSJSONSerialization JSONObjectWithData:[string(sample_json) dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
            for (NSString *label in samples) output[[@"byhost_known_file_data_" stringByAppendingString:label]] = read_source_file([samples[label] fileSystemRepresentation], key);
        }
        if (argc == 3) {
            NSDictionary *operations = replica_write_operations(argv[2]);
            for (NSString *name in operations) output[[@"replica_write_" stringByAppendingString:name]] = operations[name];
        }

        io_service_t platform = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
        for (NSString *property in @[@"IOPlatformUUID", @"IOPlatformSerialNumber", @"model"]) {
            CFTypeRef value = platform ? IORegistryEntryCreateCFProperty(platform, (__bridge CFStringRef)property, kCFAllocatorDefault, 0) : NULL;
            output[[property stringByAppendingString:@"_single"]] = result(description(value), 0, nil, key);
            if (value) CFRelease(value);
        }
        CFMutableDictionaryRef properties = NULL;
        kern_return_t all_code = platform ? IORegistryEntryCreateCFProperties(platform, &properties, kCFAllocatorDefault, 0) : KERN_FAILURE;
        for (NSString *property in @[@"IOPlatformUUID", @"IOPlatformSerialNumber", @"model"]) {
            CFTypeRef value = properties ? CFDictionaryGetValue(properties, (__bridge CFStringRef)property) : NULL;
            output[[property stringByAppendingString:@"_bulk"]] = result(description(value), (int)all_code, nil, key);
        }
        if (properties) CFRelease(properties);
        if (platform) IOObjectRelease(platform);

        struct ifaddrs *addresses = NULL;
        errno = 0;
        int if_code = getifaddrs(&addresses);
        NSMutableSet *interfaces = [NSMutableSet set];
        if (if_code == 0) {
            for (struct ifaddrs *entry = addresses; entry; entry = entry->ifa_next) {
                if (entry->ifa_name) [interfaces addObject:string(entry->ifa_name)];
            }
            freeifaddrs(addresses);
        }
        output[@"getifaddrs_names"] = result(if_code == 0 ? [[[interfaces allObjects] sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@","] : nil, if_code == 0 ? 0 : errno, nil, key);

        int fd = open(argv[1], O_RDWR);
        struct stat info = {0};
        char payload[32] = {0};
        bool file_ok = fd >= 0 && fstat(fd, &info) == 0 && pread(fd, payload, 5, 0) == 5 && memcmp(payload, "probe", 5) == 0 && pwrite(fd, "probe", 5, 0) == 5;
        if (fd >= 0) close(fd);
        output[@"file_io"] = @{@"available": @(file_ok), @"inode": @(info.st_ino), @"uid_digest": digest([[NSString stringWithFormat:@"%u", info.st_uid] dataUsingEncoding:NSUTF8StringEncoding], key)};

        NSData *json = [NSJSONSerialization dataWithJSONObject:output options:0 error:nil];
        fwrite(json.bytes, 1, json.length, stdout);
        fputc('\n', stdout);
        return 0;
    }
}
