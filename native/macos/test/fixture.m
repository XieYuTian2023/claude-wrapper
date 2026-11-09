#import <Foundation/Foundation.h>
#include <assert.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    @autoreleasepool {
        if (argc == 2 && strcmp(argv[1], "--home") == 0) {
            struct passwd *entry = getpwuid(getuid());
            assert(entry);
            puts(entry->pw_dir);
            return 0;
        }

        assert(argc == 5 && strcmp(argv[4], "argument with spaces") == 0);
        const char *host = getenv("HOSTNAME");
        const char *user = getenv("USER");
        const char *zone = getenv("TZ");

        char hostname[256];
        assert(gethostname(hostname, sizeof(hostname)) == 0 && !strcmp(host, hostname));
        struct utsname uts;
        assert(uname(&uts) == 0 && !strcmp(host, uts.nodename));
        assert(!strcmp(uts.sysname, getenv("CLAUDE_WRAPPER_TEST_SYSNAME")));
        assert(!strcmp(uts.release, getenv("CLAUDE_WRAPPER_TEST_RELEASE")));
        assert(!strcmp(uts.version, getenv("CLAUDE_WRAPPER_TEST_VERSION")));
        assert(!strcmp(uts.machine, getenv("CLAUDE_WRAPPER_TEST_MACHINE")));

        struct passwd *current = getpwuid(getuid());
        assert(current && !strcmp(current->pw_name, user) && !strcmp(current->pw_dir, argv[1]));
        assert(current->pw_uid == getuid() && current->pw_gid == getgid());
        current = getpwnam(user);
        assert(current && !strcmp(current->pw_name, user) && current->pw_uid == getuid());
        struct passwd entry;
        char passwd_buffer[4096];
        assert(getpwuid_r(getuid(), &entry, passwd_buffer, sizeof(passwd_buffer), &current) == 0);
        assert(current && !strcmp(current->pw_name, user) && !strcmp(current->pw_dir, argv[1]));
        assert(current->pw_uid == getuid() && current->pw_gid == getgid());
        assert(getpwnam_r(user, &entry, passwd_buffer, sizeof(passwd_buffer), &current) == 0);
        assert(current && !strcmp(current->pw_name, user) && current->pw_uid == getuid());
        assert([NSHomeDirectory() isEqualToString:@(argv[1])]);

        assert([CFBridgingRelease(CFTimeZoneCopySystem()) name] != nil);
        assert([[CFBridgingRelease(CFTimeZoneCopySystem()) name] isEqualToString:@(zone)]);
        assert([NSTimeZone.systemTimeZone.name isEqualToString:@(zone)]);
        assert([NSTimeZone.defaultTimeZone.name isEqualToString:@(zone)]);
        assert([NSTimeZone.localTimeZone.name isEqualToString:@(zone)]);
        const time_t dates[] = { 1705276800, 1721001600 };
        for (size_t i = 0; i < sizeof(dates) / sizeof(dates[0]); i++) {
            struct tm local;
            assert(localtime_r(&dates[i], &local));
            assert(local.tm_gmtoff == strtol(argv[2 + i], NULL, 10));
        }

        assert([[CFBridgingRelease(CFLocaleCopyCurrent()) localeIdentifier] isEqualToString:@"en_US"]);
        assert([[CFBridgingRelease(CFLocaleCopyPreferredLanguages()) firstObject] isEqualToString:@"en-US"]);
        assert([NSLocale.currentLocale.localeIdentifier isEqualToString:@"en_US"]);
        assert([NSLocale.autoupdatingCurrentLocale.localeIdentifier isEqualToString:@"en_US"]);
        assert([NSLocale.preferredLanguages.firstObject isEqualToString:@"en-US"]);

        assert(!getenv("CLAUDE_WRAPPER_READY_FD") && !getenv("DYLD_INSERT_LIBRARIES"));
        assert(!getenv("CLAUDE_WRAPPER_HOSTNAME") && !getenv("CLAUDE_WRAPPER_USERNAME"));
        FILE *output = fopen("fixture-output", "wb");
        assert(output && fputs("host file\n", output) >= 0 && fclose(output) == 0);
        return 42;
    }
}
