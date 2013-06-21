#include <errno.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
//#include <asm/page.h>
#include <sys/user.h>

#include "cryopid.h"

/*Mohanish*/
int __sprintf_chk (char *__restrict __s, int __flag, size_t __slen,
                          __const char *__restrict __format, ...)
{
	return 0;
}

extern int __snprintf_chk (char *__restrict __s, size_t __n, int __flag,
                           size_t __slen, __const char *__restrict __format,
                           ...)
{
	return 0;
}

extern int __vfprintf_chk (FILE *__restrict __stream, int __flag,
                           __const char *__restrict __format, _G_va_list __ap)
{
	return 0;
}

int __fprintf_chk (FILE *__restrict __stream, int __flag,
                          __const char *__restrict __format, ...)
{
	return 0;
}


int __open_2 (__const char *__path, int __oflag)
{
	return 0;
}

ssize_t __read_chk (int __fd, void *__buf, size_t __nbytes,
                           size_t __buflen)
{
	return 0;
}

void __stack_chk_fail(void)
{
	return 0;
}

long syscall_check(int retval, int can_be_fake, char* desc, ...)
{
    va_list va_args;
    /* can_be_fake is true if the syscall might return -1 anyway, and
     * we should simply check errno.
     */
    if (can_be_fake && errno == 0) return retval;
    if (retval == -1) {
	char str[1024];
	snprintf(str, 1024, "Error in %s: %s\n", desc, strerror(errno));
	va_start(va_args, desc);
	vfprintf(stderr, str, va_args);
	va_end(va_args);
	exit(1);
    }
    return retval;
}

void safe_read(int fd, void* dest, size_t count, char* desc)
{
    int ret;
    ret = read(fd, dest, count);
    if (ret == -1) {
	fprintf(stderr, "Read error on %s: %s\n", desc, strerror(errno));
	exit(1);
    }
    if (ret < count) {
	fprintf(stderr, "Short read on %s\n", desc);
	exit(1);
    }
}

#ifdef COMPILING_STUB
/* If we're a stub, lets use a custom malloc implementation so that we don't
 * collide with pages potentially in use by the application. Here's a really
 * really stupid malloc, that simply mmaps a new VMA for each request, and rounds
 * up to the next multiple of PAGE_SIZE.
 *
 * FIXME: do something smarter. Can we persuade malloc to stick to brk'ing and
 * not mmap()?
 */

static void *cp_malloc_hook(size_t size, const void *caller)
{
    static long next_free_addr = MALLOC_START;
    int full_len = (size + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1);
    if (next_free_addr + full_len > MALLOC_END)
	return NULL; /* out of memory here */
    void *p = mmap((void*)next_free_addr, full_len, PROT_READ|PROT_WRITE,
	    MAP_FIXED, 0, 0);
	printf("Mohanish:: Error %d\n",errno);
    assert(p == (void*)next_free_addr);
    next_free_addr += full_len;
    return p;
}

static void cp_free_hook(void *ptr, const void *caller)
{
    /* Don't worry about freeing it, because our memory segment will be munmap'd
     * before the real binary executes. However this does waste memory if we
     * do lots of mallocing and freeing. FIXME. fix this.
     */
}

#ifdef PROVIDE_MALLOC
/* We provide malloc() and free() */

void *malloc(size_t size) { return cp_malloc_hook(size, NULL); }
void free(void *mem) { return cp_free_hook(mem, NULL); }

#else
/* We're hooking into libc's malloc */

static void cp_malloc_init_hook();

static void* (*old_malloc_hook)(size_t, const void *);
void (*__malloc_initialize_hook) (void) = cp_malloc_init_hook;

static void cp_malloc_init_hook()
{
    old_malloc_hook = __malloc_hook;
    __malloc_hook = cp_malloc_hook;
    __free_hook = cp_free_hook;
}

#endif /* PROVIDE_MALLOC */

#endif /* COMPILING_STUB */

void *xmalloc(int len)
{
    void *p;
    p = malloc(len);
    if (!p)
	    bail("Out of memory!");
    return p;
}

void xfree(void *p)
{
    free(p);
}

unsigned int checksum(char *ptr, int len, unsigned int start)
{
    int sum = start, i;
    for (i = 0; i < len; i++)
	sum = ((sum << 5) + sum) ^ ptr[i];
    return sum;
}

/* vim:set ts=8 sw=4 noet: */
