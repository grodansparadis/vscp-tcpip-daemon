# Unit Tests for vscpdatetime

This folder contains unit tests for the `vscpdatetime` class.

## Dependencies

- Google Test (gtest)
- OpenSSL
- EXPAT

## Building

```bash
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j4
```

## Running tests

```bash
./unittest
```

## Test coverage

The tests cover:

- **Constructors**: Default, parameterized, string, vscpEvent/vscpEventEx, Julian date, tm struct
- **Setters**: setDate, setTime, setYear, setMonth, setDay, setHour, setMinute, setSecond, setMilliSecond
- **ISO String parsing**: setISODate, setISOTime, set from string
- **Getters**: getISODateTime, getISODate, getISOTime, getJulian, getDayOfYear
- **Date calculations**: Leap year detection, week number, day of week
- **Names**: Weekday names (full/abbreviated), month names (full/abbreviated)
- **Comparisons**: isEqualTo, isEarlierThan, isLaterThan, isBetween, isStrictlyBetween, isSameDate, isSameTime
- **Operators**: +, -, +=, -=, ++, --, difference between dates
- **Static methods**: Now, UTCNow, zeroTime, zeroDate, dateTimeZero
- **Validation**: isValid
- **Constants**: MONTHS_IN_YEAR, SEC_PER_MIN, etc.
