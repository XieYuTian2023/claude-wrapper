#ifndef CLAUDE_WRAPPER_DIAGNOSTICS_H
#define CLAUDE_WRAPPER_DIAGNOSTICS_H

#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CW_ERROR_LABEL "[Wrapper/Error]"
#define CW_ERROR_COLOR "\033[1;31m"
#define CW_RESET_COLOR "\033[0m"

static inline bool cw_use_color(void)
{
    const char *term = getenv("TERM");
    return isatty(STDERR_FILENO) && !getenv("NO_COLOR") &&
        (!term || strcmp(term, "dumb") != 0);
}

static inline void cw_error(const char *format, ...)
{
    fputs(cw_use_color() ? CW_ERROR_COLOR CW_ERROR_LABEL CW_RESET_COLOR ": " :
          CW_ERROR_LABEL ": ", stderr);
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fputc('\n', stderr);
}

#endif
