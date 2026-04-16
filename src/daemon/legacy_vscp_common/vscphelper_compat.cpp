// vscphelper_compat.cpp
//
// Legacy password-hashing helpers that are not (yet) part of the submodule
// vscphelper API.  Extracted verbatim from the v14 legacy vscphelper.cpp so
// the rest of the daemon can keep calling them unchanged.
//
// SPDX-License-Identifier: MIT

#include <string.h>
#include <stdint.h>
#include <string>

#include <vscphelper.h>
#include <fastpbkdf2.h>

// ---------------------------------------------------------------------------
// vscp_makePasswordHash
// ---------------------------------------------------------------------------

bool
vscp_makePasswordHash(std::string& result,
                      const std::string& password,
                      uint8_t* pSalt)
{
    int i;
    uint8_t salt[16];
    uint8_t buf[32];

    result.clear();

    if (nullptr == pSalt) {
        if (!vscp_getSalt(salt, 16))
            return false;
    } else {
        memcpy(salt, pSalt, 16);
    }

    const size_t pwlen = password.size();
    uint8_t* p = new uint8_t[pwlen];
    if (!p)
        return false;
    memcpy(p, password.c_str(), pwlen);

    fastpbkdf2_hmac_sha256(p, pwlen, salt, 16, 70000, buf, 32);
    delete[] p;

    for (i = 0; i < 16; i++) {
        result += vscp_str_format("%02X", salt[i]);
    }
    result += ";";
    for (i = 0; i < 32; i++) {
        result += vscp_str_format("%02X", buf[i]);
    }

    return true;
}

// ---------------------------------------------------------------------------
// vscp_isPasswordValid
// ---------------------------------------------------------------------------

bool
vscp_isPasswordValid(const std::string& stored_pw, const std::string& password)
{
    std::string calcHash;
    uint8_t salt[16];
    uint8_t hash[32];

    if (!vscp_getHashPasswordComponents(salt, hash, stored_pw))
        return false;

    if (!vscp_makePasswordHash(calcHash, password, salt))
        return false;

    return (stored_pw == calcHash);
}
