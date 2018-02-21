#include <stdarg.h>

/* declared by nsexec */
extern int enable_verbose;

__attribute__((format (printf, 1, 2)))
static inline void verbose(char *fmt, ...)
{
	va_list ap;

	if (enable_verbose) {
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
	}
}
