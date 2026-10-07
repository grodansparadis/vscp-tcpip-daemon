#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#include <io.h>
#include <time.h>

#define chdir _chdir
#define unlink _unlink

#ifdef sleep
#undef sleep
#endif

static inline unsigned int
sleep(unsigned int seconds)
{
    Sleep(seconds * 1000U);
    return 0;
}

static inline int
usleep(unsigned int microseconds)
{
    Sleep((microseconds + 999U) / 1000U);
    return 0;
}

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME TIME_UTC
#endif

static inline int
clock_gettime(int clock_id, struct timespec* ts)
{
    (void)clock_id;
    return timespec_get(ts, TIME_UTC) == TIME_UTC ? 0 : -1;
}
#endif
