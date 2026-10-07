#pragma once

#ifdef _WIN32
#include <string.h>

#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#endif