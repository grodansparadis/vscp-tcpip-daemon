#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#include <io.h>
#include <time.h>

#ifdef sleep
#undef sleep
#endif
#ifdef usleep
#undef usleep
#endif

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
#endif
