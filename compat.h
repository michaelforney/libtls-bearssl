#include <stddef.h>

#ifndef HAVE_FREEZERO
void freezero(void *, size_t);
#endif

#ifndef HAVE_REALLOCARRAY
void *reallocarray(void *, size_t, size_t);
#endif

#ifndef HAVE_TIMINGSAFE_MEMCMP
int timingsafe_memcmp(const void *, const void *, size_t);
#endif
