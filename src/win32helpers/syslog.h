#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>

#define LOG_ERR 3
#define LOG_INFO 6
#define LOG_DEBUG 7

static inline void
vscp_windows_syslog(int priority, const char* format, ...)
{
    const char* level =
      (priority == LOG_ERR) ? "ERROR" : (priority == LOG_INFO) ? "INFO" : "DEBUG";
    char prefix[16];
    char message[2048] = {};
    snprintf(prefix, sizeof(prefix), "[%s] ", level);

    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    OutputDebugStringA(prefix);
    OutputDebugStringA(message);
    OutputDebugStringA("\n");
}

#define syslog(priority, ...) vscp_windows_syslog((priority), __VA_ARGS__)
#endif