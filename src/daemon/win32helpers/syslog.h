// syslog.h — Windows stub
//
// Provides the syslog priority-level constants used by daemon code so that
// files that #include <syslog.h> compile on Windows without errors.
// The actual logging is handled by canal_macro.h which maps SYSLOG() calls
// to spdlog on Linux and to a no-op on Windows.
//
// SPDX-License-Identifier: MIT

#pragma once

#ifndef _WIN32_SYSLOG_H_
#define _WIN32_SYSLOG_H_

/* syslog priority levels (RFC 3164) */
#define LOG_EMERG   0  /* system is unusable */
#define LOG_ALERT   1  /* action must be taken immediately */
#define LOG_CRIT    2  /* critical conditions */
#define LOG_ERR     3  /* error conditions */
#define LOG_WARNING 4  /* warning conditions */
#define LOG_NOTICE  5  /* normal but significant condition */
#define LOG_INFO    6  /* informational */
#define LOG_DEBUG   7  /* debug-level messages */

/* Mask of priority bits */
#define LOG_PRIMASK 0x07

/* Facilities (not used on Windows but included for source compatibility) */
#define LOG_KERN   (0 << 3)
#define LOG_USER   (1 << 3)
#define LOG_DAEMON (3 << 3)
#define LOG_LOCAL0 (16 << 3)

/* openlog / closelog / syslog are no-ops on Windows (canal_macro.h overrides) */
#ifndef openlog
#define openlog(ident, option, facility) ((void)0)
#endif
#ifndef closelog
#define closelog() ((void)0)
#endif
#ifndef syslog
#define syslog(priority, fmt, ...) ((void)0)
#endif

#endif /* _WIN32_SYSLOG_H_ */
