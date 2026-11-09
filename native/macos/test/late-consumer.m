#import <Foundation/Foundation.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

uint32_t cw_consumer_probe(void)
{
    const char *timezone = getenv("TZ");
    if (!timezone) return 0;
    @autoreleasepool {
        uint32_t mask = 0;
        CFLocaleRef locale = CFLocaleCopyCurrent();
        if (locale && [(__bridge NSString *)CFLocaleGetIdentifier(locale) isEqualToString:@"en_US"]) mask |= 64;
        if (locale) CFRelease(locale);
        CFTimeZoneRef zone = CFTimeZoneCopySystem();
        if (zone && [(__bridge NSString *)CFTimeZoneGetName(zone) isEqualToString:@(timezone)]) mask |= 32;
        if (zone) CFRelease(zone);
        CFArrayRef languages = CFLocaleCopyPreferredLanguages();
        if (languages && CFArrayGetCount(languages) == 1 &&
            CFEqual(CFArrayGetValueAtIndex(languages, 0), CFSTR("en-US"))) mask |= 128;
        if (languages) CFRelease(languages);
        return mask;
    }
}
static uint32_t constructor_mask;
__attribute__((constructor)) static void consume_in_constructor(void)
{
    constructor_mask = cw_consumer_probe();
    const char *descriptor = getenv("CLAUDE_WRAPPER_TEST_CONSTRUCTOR_FD");
    if (descriptor) (void)write(atoi(descriptor), "1", 1);
}
uint32_t cw_consumer_constructor(void) { return constructor_mask; }
