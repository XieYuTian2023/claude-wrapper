#include "../macos/rebind.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const char *image_name(void *function) {
    Dl_info image;
    if (!dladdr(function, &image) || !image.dli_fname) return "unknown";
    const char *name = strrchr(image.dli_fname, '/');
    return name ? name + 1 : image.dli_fname;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    char *end = NULL;
    unsigned long iterations = strtoul(argv[2], &end, 10);
    if (!end || *end || !iterations || iterations > 100000) return 2;
    uint32_t (*self_test)(void) = dlsym(RTLD_DEFAULT, "claude_wrapper_self_test");
    int native_expected = getenv("CW_IO_BENCH_NATIVE_EXPECTED") != NULL;
    uint32_t self_test_mask = self_test ? self_test() : 0;
    if (native_expected && (!self_test || self_test_mask != CLAUDE_WRAPPER_SELF_TEST_ALL)) {
        fputs("native provider verification failed\n", stderr);
        return 3;
    }
    if (!native_expected && self_test) return 3;
    uint64_t checksum = 0;
    uint64_t first_inode = 0;
    uid_t owner = getuid();
    uint64_t started = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
    for (unsigned long i = 0; i < iterations; i++) {
        int fd = open(argv[1], O_RDONLY | O_CLOEXEC);
        struct stat info;
        unsigned char bytes[64];
        if (fd < 0 || fstat(fd, &info) != 0 || read(fd, bytes, sizeof(bytes)) != sizeof(bytes) || close(fd) != 0) {
            perror("ordinary file I/O failed");
            return 4;
        }
        if (info.st_uid != owner || info.st_size < 64 || (i && first_inode != info.st_ino)) return 4;
        first_inode = info.st_ino;
        checksum += bytes[0] + bytes[63];
    }
    uint64_t elapsed = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) - started;
    printf("{\"iterations\":%lu,\"elapsed_ns\":%llu,\"ns_per_iteration\":%.9f,"
           "\"checksum\":%llu,\"native_provider_loaded\":%s,\"native_self_test_mask\":%u,"
           "\"file_api_images\":{\"open\":\"%s\",\"fstat\":\"%s\",\"read\":\"%s\",\"close\":\"%s\"}}\n",
           iterations, (unsigned long long)elapsed, (double)elapsed / iterations,
           (unsigned long long)checksum, self_test ? "true" : "false", self_test_mask,
           image_name((void *)open), image_name((void *)fstat), image_name((void *)read), image_name((void *)close));
    return 0;
}
