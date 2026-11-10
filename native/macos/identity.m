#import <Foundation/Foundation.h>
#import <objc/runtime.h>

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "rebind.h"
#include "../diagnostics.h"

#define INTERPOSE(replacement, original)                                      \
    __attribute__((used, section("__DATA,__interpose")))                        \
    static const struct { const void *new_function; const void *old_function; } \
    interpose_##original = { (const void *)&replacement, (const void *)&original }

#define READY_FD "CLAUDE_WRAPPER_READY_FD"

static pthread_once_t profile_once = PTHREAD_ONCE_INIT;
static char profile_timezone[256];
static char profile_locale[256];
static bool bun_initialization_owner;

static void copy_env(char *buffer, size_t size, const char *key)
{
    const char *value = getenv(key);
    if (value && strlen(value) < size) {
        strlcpy(buffer, value, size);
    }
}

static void load_profile(void)
{
    const char *owner = getenv("CLAUDE_WRAPPER_INIT_OWNER");
    bun_initialization_owner = owner && !strcmp(owner, "bun");
    copy_env(profile_timezone, sizeof(profile_timezone), "TZ");
    copy_env(profile_locale, sizeof(profile_locale), "LC_ALL");
    if (!*profile_locale) {
        copy_env(profile_locale, sizeof(profile_locale), "LANG");
    }

    // Core Foundation accepts the locale identifier without POSIX's codeset.
    char *codeset = strchr(profile_locale, '.');
    if (codeset) {
        char *modifier = strchr(codeset, '@');
        if (modifier) {
            memmove(codeset, modifier, strlen(modifier) + 1);
        } else {
            *codeset = '\0';
        }
    }
}

static _Atomic(CFTimeZoneRef) configured_timezone;
static _Atomic(CFLocaleRef) configured_locale;
static _Atomic(CFArrayRef) configured_languages;

// Hold the immutable objects for the life of the process. The atomic pointers
// publish them to any threads started by earlier library initializers.
static NSTimeZone *timezone_owner;
static NSLocale *locale_owner;
static NSArray *languages_owner;

static CFTimeZoneRef wrapper_system_timezone(void) CF_RETURNS_RETAINED
{
    CFTimeZoneRef timezone = atomic_load_explicit(&configured_timezone, memory_order_acquire);
    if (timezone) {
        return CFRetain(timezone);
    }
    return CFTimeZoneCopySystem();
}
INTERPOSE(wrapper_system_timezone, CFTimeZoneCopySystem);

static CFLocaleRef wrapper_current_locale(void) CF_RETURNS_RETAINED
{
    CFLocaleRef locale = atomic_load_explicit(&configured_locale, memory_order_acquire);
    if (locale) {
        return CFRetain(locale);
    }
    return CFLocaleCopyCurrent();
}
INTERPOSE(wrapper_current_locale, CFLocaleCopyCurrent);

static CFArrayRef wrapper_preferred_languages(void) CF_RETURNS_RETAINED
{
    CFArrayRef languages = atomic_load_explicit(&configured_languages, memory_order_acquire);
    if (languages) {
        return CFRetain(languages);
    }
    return CFLocaleCopyPreferredLanguages();
}
INTERPOSE(wrapper_preferred_languages, CFLocaleCopyPreferredLanguages);

static NSTimeZone *system_timezone(id self, SEL selector)
{
    (void)self;
    (void)selector;
    return (__bridge NSTimeZone *)atomic_load_explicit(&configured_timezone, memory_order_acquire);
}

static NSLocale *current_locale(id self, SEL selector)
{
    (void)self;
    (void)selector;
    return (__bridge NSLocale *)atomic_load_explicit(&configured_locale, memory_order_acquire);
}

static NSArray<NSString *> *preferred_languages(id self, SEL selector)
{
    (void)self;
    (void)selector;
    return (__bridge NSArray *)atomic_load_explicit(&configured_languages, memory_order_acquire);
}

static void replace_class_method(Class class, SEL selector, IMP implementation)
{
    Method method = class_getClassMethod(class, selector);
    if (method) {
        method_setImplementation(method, implementation);
    }
}

static pthread_once_t activation_once = PTHREAD_ONCE_INIT;
static _Atomic(int) activation_result = EAGAIN;
static _Atomic(uint32_t) activation_mask;

uint32_t claude_wrapper_self_test(void)
{
    pthread_once(&profile_once, load_profile);
    if (!*profile_timezone || !*profile_locale) return 0;
    uint32_t mask = 0;
    @autoreleasepool {
        CFTimeZoneRef zone = wrapper_system_timezone();
        if (zone && [(__bridge NSString *)CFTimeZoneGetName(zone) isEqualToString:@(profile_timezone)]) mask |= 32;
        if (zone) CFRelease(zone);
        CFLocaleRef locale = wrapper_current_locale();
        if (locale && [(__bridge NSString *)CFLocaleGetIdentifier(locale) isEqualToString:@(profile_locale)]) mask |= 64;
        if (locale) CFRelease(locale);
        CFArrayRef languages = wrapper_preferred_languages();
        CFStringRef identifier = CFStringCreateWithCString(NULL, profile_locale, kCFStringEncodingUTF8);
        CFStringRef expected = identifier ? CFLocaleCreateCanonicalLanguageIdentifierFromString(NULL, identifier) : NULL;
        if (languages && expected && CFArrayGetCount(languages) == 1 &&
            CFEqual(CFArrayGetValueAtIndex(languages, 0), expected)) mask |= 128;
        if (expected) CFRelease(expected);
        if (identifier) CFRelease(identifier);
        if (languages) CFRelease(languages);
    }
    return mask;
}

static void activate_imports(void)
{
    uint32_t mask = claude_wrapper_self_test();
    atomic_store(&activation_mask, mask);
    if (mask != CLAUDE_WRAPPER_SELF_TEST_ALL) { activation_result = EINVAL; return; }
    static const struct cw_binding bindings[] = {
        { "CFTimeZoneCopySystem", wrapper_system_timezone },
        { "CFLocaleCopyCurrent", wrapper_current_locale },
        { "CFLocaleCopyPreferredLanguages", wrapper_preferred_languages },
    };
    activation_result = cw_rebind_start(bindings, sizeof(bindings) / sizeof(bindings[0]));
}

int claude_wrapper_activate(void)
{
    pthread_once(&activation_once, activate_imports);
    return activation_result;
}

int claude_wrapper_get_status(void *buffer, size_t size)
{
    if (!buffer || size < sizeof(struct claude_wrapper_status)) return EINVAL;
    struct claude_wrapper_status status;
    int error = cw_rebind_status(&status);
    if (error) return error;
    if (activation_result != 0) status.activation_error = activation_result;
    status.self_test_mask = atomic_load(&activation_mask);
    status.active = activation_result == 0 && status.activation_error == 0;
    memcpy(buffer, &status, sizeof(status));
    return 0;
}

int claude_wrapper_clear_bootstrap(void)
{
    if (activation_result != 0) return EAGAIN;
    // Bun keeps a separate environment map. Publish the validated relay to C
    // clients as well, and remove the inherited preload before native execs.
    // The JS owner calls this only after its URL and client-state checks.
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    static bool finished;
    int error = pthread_mutex_lock(&mutex);
    if (error) return error;
    if (finished) { pthread_mutex_unlock(&mutex); return 0; }
    if (bun_initialization_owner) {
        const char *proxy = getenv("CLAUDE_WRAPPER_PROXY_URL");
        const char *names[] = { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
            "http_proxy", "https_proxy", "all_proxy" };
        if (proxy) {
            // setenv can replace environ storage, so retain an independent copy.
            char *copy = strdup(proxy);
            if (!copy) { error = ENOMEM; goto done; }
            for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
                if (setenv(names[i], copy, 1) != 0) { error = errno; break; }
            }
            free(copy);
            if (error) goto done;
            if (setenv("NO_PROXY", "", 1) || setenv("no_proxy", "", 1)) {
                error = errno; goto done;
            }
        }
        const char *previous = getenv("CLAUDE_WRAPPER_ORIGINAL_BUN_OPTIONS");
        if (previous) {
            char *copy = strdup(previous);
            if (!copy) { error = ENOMEM; goto done; }
            if (setenv("BUN_OPTIONS", copy, 1)) error = errno;
            free(copy);
        } else if (unsetenv("BUN_OPTIONS")) error = errno;
        if (error) goto done;
    }
    const char *keys[] = {
        "CLAUDE_WRAPPER_NATIVE_LIBRARY", "CLAUDE_WRAPPER_INIT_OWNER",
        "CLAUDE_WRAPPER_PROXY_URL", "CLAUDE_WRAPPER_DEVICE_ID",
        "CLAUDE_WRAPPER_READY_FD", "CLAUDE_WRAPPER_PRELOAD_FD",
        "CLAUDE_WRAPPER_ORIGINAL_BUN_OPTIONS",
        "CLAUDE_WRAPPER_DIAGNOSTICS",
    };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        if (unsetenv(keys[i]) != 0) { error = errno; goto done; }
    finished = true;
done:
    pthread_mutex_unlock(&mutex);
    return error;
}

static void announce_loaded(void)
{
    // Read ownership from the constructor's C-environ snapshot. Bun's JS
    // process.env map does not reliably mutate the native C environment.
    if (bun_initialization_owner) return;
    const char *value = getenv(READY_FD);
    if (!value || !*value) {
        return;
    }
    char *end;
    errno = 0;
    long fd = strtol(value, &end, 10);
    if (errno || *end || fd < 3 || fd > INT_MAX) {
        _exit(126);
    }
    struct stat status;
    if (fstat((int)fd, &status) != 0 || !S_ISFIFO(status.st_mode)) {
        _exit(126);
    }

    // The main image is the only process for which the helper checks injection.
    unsetenv(READY_FD);
    unsetenv("DYLD_INSERT_LIBRARIES");
    ssize_t written;
    do {
        written = write((int)fd, "1", 1);
    } while (written < 0 && errno == EINTR);
    close((int)fd);
    if (written != 1) {
        _exit(126);
    }
}

__attribute__((constructor))
static void initialize_shim(void)
{
    pthread_once(&profile_once, load_profile);
    CFTimeZoneRef timezone = NULL;
    CFLocaleRef locale = NULL;
    @autoreleasepool {
        if (*profile_timezone) {
            CFStringRef name = CFStringCreateWithCString(NULL, profile_timezone,
                                                         kCFStringEncodingUTF8);
            if (name) {
                timezone = CFTimeZoneCreateWithName(NULL, name, false);
                CFRelease(name);
            }
            if (timezone) {
                timezone_owner = CFBridgingRelease(timezone);
                atomic_store_explicit(&configured_timezone, timezone, memory_order_release);
                CFTimeZoneSetDefault(timezone);
                replace_class_method(NSTimeZone.class, @selector(systemTimeZone),
                                     (IMP)system_timezone);
            }
        }
        if (*profile_locale) {
            CFStringRef name = CFStringCreateWithCString(NULL, profile_locale,
                                                         kCFStringEncodingUTF8);
            CFArrayRef languages = NULL;
            if (name) {
                locale = CFLocaleCreate(NULL, name);
                CFStringRef language = CFLocaleCreateCanonicalLanguageIdentifierFromString(NULL,
                                                                                           name);
                if (language) {
                    const void *values[] = { language };
                    languages = CFArrayCreate(NULL, values, 1, &kCFTypeArrayCallBacks);
                    CFRelease(language);
                }
                CFRelease(name);
            }
            if (locale) {
                locale_owner = CFBridgingRelease(locale);
                atomic_store_explicit(&configured_locale, locale, memory_order_release);
                replace_class_method(NSLocale.class, @selector(currentLocale),
                                     (IMP)current_locale);
                replace_class_method(NSLocale.class, @selector(autoupdatingCurrentLocale),
                                     (IMP)current_locale);
            }
            if (languages) {
                languages_owner = CFBridgingRelease(languages);
                atomic_store_explicit(&configured_languages, languages, memory_order_release);
                replace_class_method(NSLocale.class, @selector(preferredLanguages),
                                     (IMP)preferred_languages);
            }
        }
    }
    if (!bun_initialization_owner && getenv(READY_FD) &&
        (!timezone || !locale || !atomic_load(&configured_languages))) {
        const char *message = cw_use_color() ? CW_ERROR_COLOR CW_ERROR_LABEL CW_RESET_COLOR
            ": invalid native profile\n" : CW_ERROR_LABEL ": invalid native profile\n";
        write(STDERR_FILENO, message, strlen(message));
        _exit(126);
    }
    announce_loaded();
}
