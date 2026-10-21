# Building from source

The daemon is built with CMake and requires a C99 and C++17 compiler, CMake
3.16 or newer, and the platform development libraries listed below. CMake
downloads the pinned VSCP source and other bundled dependencies during
configuration, so the first configure requires network access.

## Linux

On Debian or Ubuntu, install the build tools and development packages:

```bash
sudo apt update
sudo apt install build-essential cmake ninja-build pkg-config \
  libssl-dev libexpat1-dev zlib1g-dev libcurl4-openssl-dev \
  libsqlite3-dev libmosquitto-dev libsystemd-dev libsodium-dev
```

Configure and build a release binary:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

The daemon is written to `build/bin/vscpd`. To build with the regression-test
targets enabled, configure with `-DVSCPD_BUILD_TESTS=ON`:

```bash
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DVSCPD_BUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The tests option is off by default. Some black-box tests are available only on
Unix-like systems, and the Python binary-protocol suite is registered only
when Python 3 and its `cryptography` and `pynacl` modules are installed. See
the [test definitions](../tests/CMakeLists.txt) for the current targets.

## macOS

Install CMake, Ninja and the required libraries with Homebrew:

```bash
brew install cmake ninja openssl expat mosquitto zlib curl libsodium
```

Configure with Homebrew's OpenSSL, curl and expat paths, then build:

```bash
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR="$(brew --prefix openssl)" \
  -DCURL_ROOT="$(brew --prefix curl)" \
  -DEXPAT_INCLUDE_DIR="$(brew --prefix expat)/include" \
  -DEXPAT_LIBRARY="$(brew --prefix expat)/lib/libexpat.dylib" \
  -DCMAKE_PREFIX_PATH="$(brew --prefix openssl);$(brew --prefix curl);$(brew --prefix expat)"
cmake --build build --parallel
```

## Windows

Build with Visual Studio 2022 and vcpkg. Install the `x64-windows` packages
`openssl`, `expat`, `zlib`, `curl`, `mosquitto`, `dlfcn-win32`, `libsodium`,
`sqlite3` and `pthreads`, then configure and build from a Visual Studio
Developer PowerShell:

```powershell
cmake -S . -B build `
  -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_INSTALLATION_ROOT\scripts\buildsystems\vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows
cmake --build build --config Release --parallel
```

The project CI workflows contain the platform-specific dependency and package
steps: [Linux](../.github/workflows/linux.yml),
[macOS](../.github/workflows/macos.yml) and
[Windows](../.github/workflows/windows.yml).

## Packages

After building, run CPack from the build directory to create an archive:

```bash
cd build
cpack -G TGZ
```

Package generators differ by platform and may require additional packaging
tools. The CI workflows show the generator sets used for each platform.

If you need to change the VSCP source revision used by CMake, follow
[Updating the pinned VSCP source](updating_pinned_vscp_source.md).
