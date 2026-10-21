# Updating the Pinned VSCP Source

The build downloads the VSCP sources as a source tarball pinned to one commit of
[grodansparadis/vscp](https://github.com/grodansparadis/vscp). The `vscp`
`FetchContent_Declare` in the repository's [CMakeLists.txt](../CMakeLists.txt)
sets the URL and checksum:

```cmake
URL https://codeload.github.com/grodansparadis/vscp/tar.gz/<commit>
URL_HASH SHA256=<sha256 of the tarball>
```

To use a later commit:

1. Find the full 40-character commit ID you want, for example the latest on
   `master`:

   ```bash
   git ls-remote https://github.com/grodansparadis/vscp.git refs/heads/master
   ```

2. Compute the SHA256 of that commit's tarball:

   ```bash
   COMMIT=<commit>
   curl -fsSL "https://codeload.github.com/grodansparadis/vscp/tar.gz/${COMMIT}" | sha256sum
   ```

3. In `CMakeLists.txt`, replace the commit at the end of `URL` with the new
   commit ID. Replace the value after `URL_HASH SHA256=` with the 64-character
   checksum from step 2. Do not use the commit ID as the checksum. If the
   checksum doesn't match, CMake deletes every download and reports
   `Each download failed!`.

4. Reconfigure so CMake downloads the new sources, then rebuild:

   ```bash
   cmake -S . -B build
   cmake --build build
   ```

   If the build still uses the old sources, delete `build/_deps/vscp-*` or use
   **CMake: Delete Cache and Reconfigure** in VS Code.

If the new VSCP commit adds, renames, or removes source files that vscpd
compiles, update the source list in `CMakeLists.txt` to match.
