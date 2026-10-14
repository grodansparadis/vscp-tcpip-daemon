# cguid Unit Tests

Unit tests for the cguid class.

## Building

```bash
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j4
```

## Running Tests

```bash
./unittest
```

## Test Categories

- **Constructor tests** - Default, array, copy, string constructors
- **Operator tests** - Assignment, equality, inequality, index operators  
- **Clear/isNULL tests** - Clearing GUID and checking for null
- **String conversion tests** - Parsing and formatting GUIDs
- **Array operations tests** - Reading/writing to byte arrays
- **Byte access tests** - Get/set individual bytes, LSB/MSB
- **Client ID tests** - Setting/getting client ID (bytes 12-13)
- **Nickname ID tests** - Setting/getting nickname ID (bytes 14-15)
- **Comparison tests** - isSameGUID functionality
- **Edge cases** - Lowercase/mixed case hex, partial strings
