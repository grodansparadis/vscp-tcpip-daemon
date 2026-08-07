// unistd.h — Windows stub
//
// Provides minimal POSIX unistd.h compatibility for daemon code compiled
// on Windows (MSVC).  Only the functions actually used by the daemon
// sources are defined here; extend as needed.
//
// We use <synchapi.h> (rather than the heavier <windows.h>) to obtain Sleep()
// so that including this header does not disturb the winsock2/winsock include
// order in translation units that need socket types.
//
// SPDX-License-Identifier: MIT

#pragma once

#ifndef _WIN32_UNISTD_H_
#define _WIN32_UNISTD_H_

#include <synchapi.h>

/* usleep — sleep for the given number of microseconds.
   Windows Sleep() resolution is milliseconds; we round up to avoid
   sleeping shorter than requested. */
static inline void
usleep(unsigned long usec)
{
    Sleep((DWORD)((usec + 999UL) / 1000UL));
}

#endif /* _WIN32_UNISTD_H_ */
