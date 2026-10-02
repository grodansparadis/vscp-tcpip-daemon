# vscpdatetime Class Reference

The `vscpdatetime` class provides date and time handling for the VSCP system. It stores time internally as a 64-bit nanosecond timestamp since the Unix epoch, supporting high-precision timing and dates both before and after 1970.

## Header

```cpp
#include "vscpdatetime.h"
```

## Overview

The class uses a signed 64-bit nanosecond timestamp (`int64_t`) internally, allowing:
- Nanosecond precision
- Dates before 1970 (negative timestamps)
- Range of approximately ±292 years from 1970

## Constants

### Time Units
| Constant | Value | Description |
|----------|-------|-------------|
| `MONTHS_IN_YEAR` | 12 | Months per year |
| `SEC_PER_MIN` | 60 | Seconds per minute |
| `MIN_PER_HOUR` | 60 | Minutes per hour |
| `SECONDS_PER_HOUR` | 3600 | Seconds per hour |
| `SECONDS_PER_DAY` | 86400 | Seconds per day |
| `DAYS_PER_WEEK` | 7 | Days per week |
| `MILLISECONDS_PER_DAY` | 86400000 | Milliseconds per day |
| `EPOCH_JDN` | 2440587 | Julian Day Number of Jan 1, 1970 |

### Internal Constants (private)
| Constant | Value |
|----------|-------|
| `NS_PER_MICROSECOND` | 1,000 |
| `NS_PER_MILLISECOND` | 1,000,000 |
| `NS_PER_SECOND` | 1,000,000,000 |
| `NS_PER_MINUTE` | 60 × NS_PER_SECOND |
| `NS_PER_HOUR` | 60 × NS_PER_MINUTE |
| `NS_PER_DAY` | 24 × NS_PER_HOUR |

---

## Enumerations

### weekDay
```cpp
enum weekDay { Sun, Mon, Tue, Wed, Thu, Fri, Sat, Inv_WeekDay };
```

### month
```cpp
enum month { Jan, Feb, Mar, Apr, May, Jun, Jul, Aug, Sep, Oct, Nov, Dec, Inv_Month };
```
Note: Months are 0-indexed (Jan = 0, Dec = 11).

### nameFlags
```cpp
enum nameFlags { name_Full = 0x01, name_Abbr = 0x02 };
```
Used for formatting month and weekday names.

### weekFlags
```cpp
enum weekFlags { Default_First, Monday_First, Sunday_First };
```
Used for week number calculations.

---

## Constructors

### Default Constructor
```cpp
vscpdatetime(void);
```
Initializes to current UTC time.

### String Constructor
```cpp
vscpdatetime(const std::string& dt);
```
Parses an ISO 8601 datetime string.

**Parameters:**
- `dt` - String in format `YYYY-MM-DDTHH:MM:SS`

### VSCP Event Constructor
```cpp
vscpdatetime(vscpEvent& ev);
vscpdatetime(vscpEventEx& ex);
```
Initializes from a VSCP event's timestamp fields.

### Component Constructor
```cpp
vscpdatetime(uint16_t year, uint8_t month, uint8_t day,
             uint8_t hour, uint8_t minute, uint8_t second,
             uint32_t millisecond = 0);
```
Creates from individual date/time components.

**Parameters:**
- `year` - Year (e.g., 2026)
- `month` - Month (0-11, where 0 = January)
- `day` - Day of month (1-31)
- `hour` - Hour (0-23)
- `minute` - Minute (0-59)
- `second` - Second (0-59)
- `millisecond` - Millisecond (0-999), optional

### Julian Date Constructor
```cpp
vscpdatetime(const long ljd);
vscpdatetime(const double ljd);
```
Creates from Julian Day Number.

### Unix tm Struct Constructor
```cpp
vscpdatetime(const struct tm& tm);
```
Creates from standard C `tm` structure.

---

## Static Factory Methods

### Now / UTCNow
```cpp
static vscpdatetime Now(void);
static vscpdatetime UTCNow(void);
```
Returns current local or UTC time.

### fromTimestamp
```cpp
static vscpdatetime fromTimestamp(int64_t timestamp);
```
Creates from a 64-bit nanosecond Unix timestamp.

**Example:**
```cpp
// Create from nanosecond timestamp
int64_t ns = 1741795200000000000LL;  // March 12, 2025 12:00:00 UTC
vscpdatetime dt = vscpdatetime::fromTimestamp(ns);
```

### Zero Values
```cpp
static vscpdatetime zeroTime(void);     // Midnight
static vscpdatetime zeroDate(void);     // First date
static vscpdatetime dateTimeZero(void); // Both zeroed
```

---

## Setting Methods

### set (Full datetime)
```cpp
bool set(uint16_t year, uint8_t month, uint8_t day,
         uint8_t hour, uint8_t minute, uint8_t second,
         uint32_t millisecond = 0);
bool set(std::string dt);
bool set(const char* pdt);
bool set(vscpEvent& ev);
bool set(vscpEventEx& ex);
bool set(const struct tm& tm);
```
Sets the datetime from various sources.

### setDate
```cpp
bool setDate(uint16_t year, uint8_t month, uint8_t day);
bool setISODate(const std::string& strDate);
bool setISODate(const char* pDate);
```
Sets only the date portion. ISO format: `YYYY-MM-DD`

### setTime
```cpp
bool setTime(uint8_t hour, uint8_t minute, uint8_t second,
             uint32_t millisecond = 0);
bool setISOTime(const std::string& strTime);
bool setISOTime(const char* pTime);
```
Sets only the time portion. ISO format: `HH:MM:SS`

### setFromJulian
```cpp
void setFromJulian(const long ljd);
```
Sets date from Julian Day Number.

### setNow / setUTCNow
```cpp
void setNow(void);
void setUTCNow(void);
```
Sets to current local or UTC time.

### setNowIfTimeStampRelative
```cpp
bool setNowIfTimeStampRelative(void);
```
Sets to current UTC time only if the timestamp is less than one second (useful for initializing unset timestamps). Preserves the sub-second nanosecond portion.

**Returns:** `true` if timestamp was updated, `false` if already valid.

**Example:**
```cpp
vscpdatetime dt;
dt.setTimestamp(500000000);  // 0.5 seconds (relative timestamp)
dt.setNowIfTimeStampRelative();  // Sets to now, keeps 0.5s offset
```

### Individual Component Setters
```cpp
bool setYear(uint16_t year);
bool setMonth(uint8_t month);
bool setDay(uint8_t day);
bool setHour(uint8_t hour);
bool setMinute(uint8_t minute);
bool setSecond(uint8_t second);
bool setMilliSecond(uint32_t millisecond);
void setTimestamp(int64_t timestamp);
```

---

## Getting Methods

### Individual Components
```cpp
uint16_t getYear(void) const;
month getMonth(void) const;        // Returns enum (0-11)
uint8_t getDay(void) const;        // 1-31
uint8_t getHour(void) const;       // 0-23
uint8_t getMinute(void) const;     // 0-59
uint8_t getSecond(void) const;     // 0-59
```

### Sub-second Precision
```cpp
uint32_t getMilliSeconds(void) const;  // 0-999
uint32_t getMicroSeconds(void) const;  // 0-999999
uint32_t getNanoSeconds(void) const;   // 0-999999999 (sub-second only)
```

### Raw Timestamp
```cpp
int64_t getTimestamp(void) const;
```
Returns nanoseconds since Unix epoch. Can be negative for pre-1970 dates.

### String Formats
```cpp
std::string getISODateTime(bool bSeparator = true) const;
std::string getISODate(void);
std::string getISOTime(void);
```

**Examples:**
```cpp
vscpdatetime dt(2026, 2, 12, 14, 30, 45);  // March 12, 2026 (month is 0-indexed)
dt.getISODateTime();     // "2026-03-12T14:30:45"
dt.getISODateTime(false); // "2026-03-1214:30:45" (no 'T' separator)
dt.getISODate();         // "2026-03-12"
dt.getISOTime();         // "14:30:45"
```

### Julian Day
```cpp
long getJulian(void);
```
Returns the Julian Day Number.

### Day of Year
```cpp
int getDayOfYear(void) const;
```
Returns day number within the year (1-366).

### Week Information
```cpp
int getWeekNumber(void) const;
weekDay getWeekDay(void) const;
```

### System Time
```cpp
time_t toSysTime(void) const;
```
Converts to standard C `time_t`.

---

## Static Name Methods

```cpp
static std::string getWeekDayName(weekDay weekday, 
                                  nameFlags flags = name_Full);
static std::string getMonthName(month month,
                                nameFlags flags = name_Full);
```

**Examples:**
```cpp
vscpdatetime::getWeekDayName(vscpdatetime::Mon);           // "Monday"
vscpdatetime::getWeekDayName(vscpdatetime::Mon, name_Abbr); // "Mon"
vscpdatetime::getMonthName(vscpdatetime::Mar);             // "March"
vscpdatetime::getMonthName(vscpdatetime::Mar, name_Abbr);  // "Mar"
```

---

## Validation Methods

```cpp
bool isValid(void);
bool isLeapYear(void);
```

---

## Comparison Methods

```cpp
bool isEqualTo(vscpdatetime& dt);
bool isEarlierThan(vscpdatetime& dt);
bool isLaterThan(vscpdatetime& dt);
bool isBetween(vscpdatetime& t1, vscpdatetime& t2);
bool isStrictlyBetween(vscpdatetime& t1, vscpdatetime& t2);
bool isSameDate(vscpdatetime& dt) const;
bool isSameTime(vscpdatetime& dt) const;
```

### Difference
```cpp
static double diffSeconds(vscpdatetime& t1, vscpdatetime& t2);
```
Returns difference in seconds between two datetimes.

---

## Operators

### Arithmetic (adds/subtracts days)
```cpp
vscpdatetime operator+(const vscpdatetime& Left, const long Right);
vscpdatetime operator+(const long Left, const vscpdatetime& Right);
vscpdatetime& operator+=(const long Right);

vscpdatetime operator-(const vscpdatetime& Left, const long Right);
vscpdatetime operator-(const long Left, const vscpdatetime& Right);
vscpdatetime& operator-=(const long Right);

long operator-(vscpdatetime& Right);  // Difference in days
```

### Increment/Decrement (by one day)
```cpp
vscpdatetime& operator++();    // Prefix
vscpdatetime operator++(int);  // Postfix
vscpdatetime& operator--();    // Prefix
vscpdatetime operator--(int);  // Postfix
```

**Example:**
```cpp
vscpdatetime dt(2026, 2, 12, 12, 0, 0);  // March 12, 2026
dt += 7;   // March 19, 2026
dt++;      // March 20, 2026
dt = dt - 10;  // March 10, 2026
```

---

## Timezone Methods

```cpp
static int tzOffset2LocalTime(void);
static long tz_offset_second(time_t t);
```

---

## Example Usage

```cpp
#include "vscpdatetime.h"
#include <iostream>

int main() {
    // Create current UTC time
    vscpdatetime now = vscpdatetime::UTCNow();
    std::cout << "Now: " << now.getISODateTime() << std::endl;
    
    // Create specific date/time (month is 0-indexed!)
    vscpdatetime dt(2026, 2, 12, 14, 30, 45);  // March 12, 2026 14:30:45
    std::cout << "Date: " << dt.getISODate() << std::endl;
    std::cout << "Time: " << dt.getISOTime() << std::endl;
    
    // Parse from string
    vscpdatetime parsed;
    parsed.set("2026-03-12T10:00:00");
    
    // Create from nanosecond timestamp
    vscpdatetime fromTs = vscpdatetime::fromTimestamp(1741795200000000000LL);
    
    // Access sub-second precision
    std::cout << "Milliseconds: " << now.getMilliSeconds() << std::endl;
    std::cout << "Microseconds: " << now.getMicroSeconds() << std::endl;
    std::cout << "Nanoseconds: " << now.getNanoSeconds() << std::endl;
    
    // Raw timestamp access
    int64_t ts = now.getTimestamp();
    std::cout << "Timestamp (ns): " << ts << std::endl;
    
    // Date arithmetic
    vscpdatetime tomorrow = now + 1;
    vscpdatetime lastWeek = now - 7;
    
    // Comparisons
    if (now.isLaterThan(parsed)) {
        std::cout << "Current time is later" << std::endl;
    }
    
    // Check if timestamp is relative (< 1 second)
    vscpdatetime relative;
    relative.setTimestamp(500000000);  // 0.5 seconds
    if (relative.setNowIfTimeStampRelative()) {
        std::cout << "Timestamp was relative, now set to current time" << std::endl;
    }
    
    // Week and day info
    std::cout << "Week day: " << vscpdatetime::getWeekDayName(now.getWeekDay()) << std::endl;
    std::cout << "Month: " << vscpdatetime::getMonthName(now.getMonth()) << std::endl;
    std::cout << "Day of year: " << now.getDayOfYear() << std::endl;
    std::cout << "Week number: " << now.getWeekNumber() << std::endl;
    
    return 0;
}
```

---

## Important Notes

1. **Month indexing**: Months are 0-indexed (January = 0, December = 11)
2. **Timestamp precision**: Internal storage uses nanoseconds for high precision
3. **Pre-1970 dates**: Supported via signed 64-bit timestamp
4. **Thread safety**: Not thread-safe; use external synchronization if needed

---

## See Also

- [VSCP Specification](https://docs.vscp.org/) - Full VSCP protocol documentation
- [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601) - Date/time format standard
