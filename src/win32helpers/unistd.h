#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#include <io.h>

#ifdef sleep
#undef sleep
#endif
#ifdef usleep
#undef usleep
#endif

#define chdir _chdir
#define unlink _unlink

static inline unsigned int
vscp_sleep(unsigned int seconds)
{
    Sleep(seconds * 1000U);
    return 0;
}

static inline int
vscp_usleep(unsigned int microseconds)
{
    Sleep((microseconds + 999U) / 1000U);
    return 0;
}

#define sleep vscp_sleep
#define usleep vscp_usleep
#endif