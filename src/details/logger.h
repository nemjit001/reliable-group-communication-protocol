#ifndef LOGGER
#define LOGGER

#include <stdarg.h>
#include <stdio.h>

void logger_init();

void logger_free();

void log_msg(const char* format, ...);

#endif
