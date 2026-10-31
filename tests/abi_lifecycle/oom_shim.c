/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
 * Copyright (c) 2026 Yandex
 *
 * License text: LICENSE.
 * Upstream notices: LICENSES/libtpms-notices.txt.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>

static volatile int armed;
static volatile unsigned long refused;

void libtpms_oom_arm(void) { armed = 1; }
void libtpms_oom_disarm(void) { armed = 0; }
unsigned long libtpms_oom_refused(void) { return refused; }

static int refuse(void)
{
    if (!armed)
        return 0;
    refused++;
    errno = ENOMEM;
    return 1;
}

#if defined(__APPLE__)

static void *oom_malloc(size_t size)
{
    return refuse() ? NULL : malloc(size);
}

static void *oom_calloc(size_t count, size_t size)
{
    return refuse() ? NULL : calloc(count, size);
}

static void *oom_realloc(void *ptr, size_t size)
{
    return refuse() ? NULL : realloc(ptr, size);
}

static int oom_posix_memalign(void **out, size_t alignment, size_t size)
{
    return refuse() ? ENOMEM : posix_memalign(out, alignment, size);
}

static void *oom_aligned_alloc(size_t alignment, size_t size)
{
    return refuse() ? NULL : aligned_alloc(alignment, size);
}

__attribute__((used)) static const struct {
    const void *replacement;
    const void *replacee;
} interpose[] __attribute__((section("__DATA,__interpose"))) = {
    {(const void *)oom_malloc, (const void *)malloc},
    {(const void *)oom_calloc, (const void *)calloc},
    {(const void *)oom_realloc, (const void *)realloc},
    {(const void *)oom_posix_memalign, (const void *)posix_memalign},
    {(const void *)oom_aligned_alloc, (const void *)aligned_alloc},
};

#elif defined(__GLIBC__)

extern void *__libc_malloc(size_t size);
extern void *__libc_calloc(size_t count, size_t size);
extern void *__libc_realloc(void *ptr, size_t size);
extern void *__libc_memalign(size_t alignment, size_t size);

void *malloc(size_t size)
{
    return refuse() ? NULL : __libc_malloc(size);
}

void *calloc(size_t count, size_t size)
{
    return refuse() ? NULL : __libc_calloc(count, size);
}

void *realloc(void *ptr, size_t size)
{
    return refuse() ? NULL : __libc_realloc(ptr, size);
}

void *memalign(size_t alignment, size_t size)
{
    return refuse() ? NULL : __libc_memalign(alignment, size);
}

void *aligned_alloc(size_t alignment, size_t size)
{
    return refuse() ? NULL : __libc_memalign(alignment, size);
}

int posix_memalign(void **out, size_t alignment, size_t size)
{
    void *ptr;

    if (refuse())
        return ENOMEM;
    ptr = __libc_memalign(alignment, size);
    if (!ptr)
        return ENOMEM;
    *out = ptr;
    return 0;
}

#else
#error "the allocation-failure shim supports macOS and glibc only"
#endif
