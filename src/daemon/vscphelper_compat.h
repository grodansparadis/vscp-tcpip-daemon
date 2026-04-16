// vscphelper_compat.h
//
// Functions present in the legacy vscphelper but not yet in the submodule.
// Included automatically by the shim vscphelper.h.
//
// SPDX-License-Identifier: MIT

#pragma once

#include <stdint.h>
#include <string>

// ---------------------------------------------------------------------------
// Password hashing helpers (PBKDF2-SHA256 based)
// ---------------------------------------------------------------------------

bool vscp_makePasswordHash(std::string& result,
                           const std::string& password,
                           uint8_t* pSalt = nullptr);

bool vscp_isPasswordValid(const std::string& stored_pw,
                          const std::string& password);
