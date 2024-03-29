#include "logger.h"

#include <pthread.h>

static pthread_mutex_t g_loggingMtx;

void logger_init()
{
    pthread_mutex_init(&g_loggingMtx, NULL);
}

void logger_free()
{
    pthread_mutex_destroy(&g_loggingMtx);
}

#ifndef NDEBUG
void log_msg(const char* format, ...)
#else
void log_msg(__attribute__((unused)) const char* format, ...)
#endif
{
#ifndef NDEBUG
    pthread_mutex_lock(&g_loggingMtx);

    va_list args;
    va_start(args, format);

    vprintf(format, args);

    va_end(args);

    pthread_mutex_unlock(&g_loggingMtx);
#endif
}
