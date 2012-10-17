#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

void fail(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);

    exit(EXIT_FAILURE);
}

void fail_if(int p, const char *fmt, ...)
{
    va_list ap;

    if (!p)
        return;

    va_start(ap, fmt);
    fprintf(stderr, "error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);

    exit(EXIT_FAILURE);
}

char* xstrdup(const char *s)
{
    char *d = strdup(s);
    fail_if(!d, "strdup");
    return d;
}

void* xalloc(size_t size)
{
    void *p = calloc(1, size);
    fail_if(!p, "calloc");
    return p;
}

