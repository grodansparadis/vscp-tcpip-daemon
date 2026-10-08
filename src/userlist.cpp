// userlist.cpp
//
// This file is part of the VSCP (https://www.vscp.org)
//
// The MIT License (MIT)
//
// Copyright (C) 2000-2026 Ake Hedman and contributors, the VSCP Project
// <info@vscp.org>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//




#ifdef __GNUG__
// #pragma implementation
#endif

#include <deque>
#include <map>
#include <string>

#include <canal-macro.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <strings.h>
#endif

#include "userlist.h"
#include <controlobject.h>
#include <vscp-aes.h>
#include <vscpdb.h>
#include <vscphelper.h>

// Forward declarations
void
vscp_md5(char* digest, const unsigned char* buf, size_t len);

///////////////////////////////////////////////////
//                 GLOBALS
///////////////////////////////////////////////////

extern CControlObject* gpobj;

// ----------------------------------------------------------------------------

/*

    const std::string pw = "correct horse battery staple";
    const std::string stored = hash_password(pw);
    std::printf("hash:   %s\n", stored.c_str());
    std::printf("good:   %s\n", verify_password(stored, pw) ? "ok" : "FAIL");
    std::printf("bad:    %s\n", verify_password(stored, "wrong") ? "FAIL" :
   "rejected");

*/

// Tune these to your server. MODERATE = ~256 MiB RAM, ~0.7 s on a typical CPU.
// INTERACTIVE = 64 MiB, ~0.1 s (the OWASP-style minimum is roughly this or
// higher). On a small/embedded box, use INTERACTIVE or lower the values
// yourself.
constexpr unsigned long long OPS_LIMIT = crypto_pwhash_OPSLIMIT_INTERACTIVE;
constexpr size_t MEM_LIMIT             = crypto_pwhash_MEMLIMIT_INTERACTIVE;

// Returns a self-contained string like
// "$argon2id$v=19$m=65536,t=2,p=1$<salt>$<hash>" Store this string in a single
// database column.
std::string
hash_password(const std::string& password)
{
    char out[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str_alg(out,
                              password.c_str(),
                              password.size(),
                              OPS_LIMIT,
                              MEM_LIMIT,
                              crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("password hashing failed (out of memory?)");
    }
    return std::string(out);
}

// Constant-time verification.
bool
verify_password(const std::string& stored_hash, const std::string& password)
{
    return crypto_pwhash_str_verify(stored_hash.c_str(),
                                    password.c_str(),
                                    password.size()) == 0;
}

// True if the stored hash uses weaker parameters than the current settings
// (or a different algorithm) and should be re-hashed at next successful login.
bool
needs_rehash(const std::string& stored_hash)
{
    return crypto_pwhash_str_needs_rehash(stored_hash.c_str(),
                                          OPS_LIMIT,
                                          MEM_LIMIT) != 0;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// Constructor
//

CUserItem::CUserItem(void)
{
    m_userID = -1; // not initialized
    m_passwordhash.clear();
    m_username.clear();

    m_fullname.clear();
    m_note.clear();
    m_listAllowedRemotes.clear();
    m_listAllowedEvents.clear();
    setAuthenticated(false);

    // Accept all events
    vscp_clearVSCPFilter(&m_filterVSCP);

    // No user rights
    m_userRights = 0x00000000;
    m_flags      = 0;
}

///////////////////////////////////////////////////////////////////////////////
// Destructor
//

CUserItem::~CUserItem(void)
{
    m_listAllowedRemotes.clear();
    m_listAllowedEvents.clear();
}

///////////////////////////////////////////////////////////////////////////////
// fixName
//

void
CUserItem::fixName(void)
{
    vscp_trim(m_username);

    // Works only for ASCII names. Should be fixed so
    // UTF8 names can be used TODO
    for (size_t i = 0; i < m_username.length(); i++) {
        switch ((const char)m_username[i]) {
            case ';':
            case '\'':
            case '\"':
            case ',':
            case ' ':
                m_username[i] = '_';
                break;
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// validatePassword
//

bool
CUserItem::validatePassword(const std::string& passwordHash)
{
    // TODO: Implement password hash validation using Argon2
    //return m_passwordhash == passwordHash;
    return verify_password(m_passwordhash.c_str(), passwordHash.c_str()) == 0;
}

///////////////////////////////////////////////////////////////////////////////
// setFromString
//
// name;password;fullname;filtermask;rights;remotes;events;note
//

bool
CUserItem::setFromString(const std::string& userSettings)
{
    std::string strToken;
    std::deque<std::string> tokens;
    vscp_split(tokens, userSettings, ";");

    // name
    if (!tokens.empty()) {
        strToken = tokens.front();
        tokens.pop_front();
        vscp_trim(strToken);
        if (strToken.length()) {
            setUserName(strToken);
            fixName();
        }
    }

    // password
    if (!tokens.empty()) {
        strToken = tokens.front();
        tokens.pop_front();
        vscp_trim(strToken);
        if (strToken.length()) {
            setPassword(strToken);
        }
    }

    // fullname
    if (!tokens.empty()) {
        strToken = tokens.front();
        tokens.pop_front();
        vscp_trim(strToken);
        if (strToken.length()) {
            setFullname(strToken);
        }
    }

    // filter
    if (!tokens.empty()) {
        strToken = tokens.front();
        tokens.pop_front();
        vscp_trim(strToken);
        if (strToken.length()) {
            setFilterFromString(strToken);
        }
    }

    // mask
    if (!tokens.empty()) {
        strToken = tokens.front();
        tokens.pop_front();
        vscp_trim(strToken);
        setFilterFromString(strToken);
    }

    // rights
    if (!tokens.empty()) {
        strToken = tokens.front();
        tokens.pop_front();
        vscp_trim(strToken);
        if (strToken.length()) {
            setUserRightsFromString(strToken);
        }
    }

    // remotes
    if (!tokens.empty()) {
        strToken = tokens.front();
        tokens.pop_front();
        vscp_trim(strToken);
        setAllowedRemotesFromString(strToken);
    }

    // events
    if (!tokens.empty()) {
        strToken = tokens.front();
        tokens.pop_front();
        vscp_trim(strToken);
        if (strToken.length()) {
            setAllowedEventsFromString(strToken);
        }
    }

    // note
    if (!tokens.empty()) {
        strToken = tokens.front();
        tokens.pop_front();
        vscp_trim(strToken);
        if (strToken.length()) {
            vscp_base64_std_decode(strToken);
            setNote(strToken);
        }
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// getAsString
//
// userid;name;password;fullname;filter;mask;rights;remotes;events;note
//

bool
CUserItem::getAsString(std::string& strUser)
{
    std::string str;
    strUser.clear();

    strUser += vscp_str_format("%ld;", getUserID());
    strUser += getUserName();
    strUser += ";";
    // Protect password
    str = getPassword();
    for (size_t i = 0; i < str.length(); i++) {
        strUser += "*";
    }
    // strUser += getPassword();
    strUser += ";";
    strUser += getFullname();
    strUser += ";";
    vscp_writeFilterToString(str, getUserFilter());
    strUser += str;
    strUser += ";";
    vscp_writeMaskToString(str, getUserFilter());
    strUser += str;
    strUser += ";";
    strUser += getUserRightsAsString();
    strUser += ";";
    strUser += getAllowedRemotesAsString();
    strUser += ";";
    strUser += getAllowedEventsAsString();
    strUser += ";";

    str = getNote();
    vscp_base64_std_encode(str);
    strUser += str;

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// getAsMap
//
// userid;name;password;fullname;filter;mask;rights;remotes;events;note
//

bool
CUserItem::getAsMap(std::map<std::string, std::string>& mapUser)
{
    std::string str, wstr;

    mapUser["userid"] = vscp_str_format("%ld;", getUserID());
    mapUser["name"]   = getUserName();

    // Protect password
    wstr = "";
    str  = getPassword();
    for (size_t i = 0; i < str.length(); i++) {
        wstr += "*";
    }
    mapUser["password"] = wstr;
    mapUser["fullname"] = getFullname();

    vscp_writeFilterToString(str, getUserFilter());
    mapUser["filter"] = str;

    vscp_writeMaskToString(str, getUserFilter());
    mapUser["mask"]    = str;
    mapUser["rights"]  = getUserRightsAsString();
    mapUser["remotes"] = getAllowedRemotesAsString();
    mapUser["events"]  = getAllowedEventsAsString();

    str = getNote();
    vscp_base64_std_encode(str);
    mapUser["note"] = str;

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// setUserRightsFromString
//

bool
CUserItem::setUserRightsFromString(const std::string& strRights)
{
    // Privileges
    if (strRights.length()) {

        m_userRights = 0;

        std::deque<std::string> tokens;
        vscp_split(tokens, strRights, "/");

        while (!tokens.empty()) {

            std::string str = tokens.front();
            tokens.pop_front();

            if (0 == strcasecmp(str.c_str(), "admin")) {
                // All rights
                m_userRights |= VSCP_ADMIN_DEFAULT_RIGHTS;
            }
            else if (0 == strcasecmp(str.c_str(), "user")) {
                // A standard user
                m_userRights |= VSCP_USER_DEFAULT_RIGHTS;
            }
            else if (0 == strcasecmp(str.c_str(), "driver")) {
                // A standard driver
                m_userRights |= VSCP_DRIVER_DEFAULT_RIGHTS;
            }
            else if (0 == strcasecmp(str.c_str(), "send-events")) {
                m_userRights |= VSCP_USER_RIGHT_ALLOW_SEND_EVENT;
            }
            else if (0 == strcasecmp(str.c_str(), "receive-events")) {
                m_userRights |= VSCP_USER_RIGHT_ALLOW_RCV_EVENT;
            }
            else if (0 == strcasecmp(str.c_str(), "l1ctrl-events")) {
                m_userRights |= VSCP_USER_RIGHT_ALLOW_SEND_L1CTRL_EVENT;
            }
            else if (0 == strcasecmp(str.c_str(), "l2ctrl-events")) {
                m_userRights |= VSCP_USER_RIGHT_ALLOW_SEND_L2CTRL_EVENT;
            }
            else if (0 == strcasecmp(str.c_str(), "hlo-events")) {
                m_userRights |= VSCP_USER_RIGHT_ALLOW_SEND_HLO_EVENT;
            }
            else if (0 == strcasecmp(str.c_str(), "shutdown")) {
                m_userRights |= VSCP_USER_RIGHT_ALLOW_SHUTDOWN;
            }
            else if (0 == strcasecmp(str.c_str(), "restart")) {
                m_userRights |= VSCP_USER_RIGHT_ALLOW_RESTART;
            }
            else if (0 == strcasecmp(str.c_str(), "interface")) {
                m_userRights |= VSCP_USER_RIGHT_ALLOW_INTERFACE;
            }
            else if (0 == strcasecmp(str.c_str(), "test")) {
                m_userRights |= VSCP_USER_RIGHT_ALLOW_TEST;
            }
            else {
                // Numerical
                uint32_t val = vscp_readStringValue(str);
                m_userRights |= val;
            }
        }
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// getAllowedEvent
//

bool
CUserItem::getAllowedEvent(size_t n, std::string& event)
{
    if (!m_listAllowedEvents.size()) {
        return false;
    }

    if (n > (m_listAllowedEvents.size() - 1)) {
        return false;
    }

    event = m_listAllowedEvents[n];
    return true;
}

///////////////////////////////////////////////////////////////////////////////
// setAllowedEvent
//

bool
CUserItem::setAllowedEvent(size_t n, std::string& event)
{
    if (!m_listAllowedEvents.size()) {
        return false;
    }

    if (n > (m_listAllowedEvents.size() - 1)) {
        return false;
    }

    m_listAllowedEvents[n] = event;
    return true;
}

///////////////////////////////////////////////////////////////////////////////
// addAllowedEvent
//

bool
CUserItem::addAllowedEvent(const std::string& strEvent)
{
    std::string str     = strEvent;
    uint16_t vscp_class = 0;
    uint16_t vscp_type  = 0;

    vscp_trim(str);

    if (str.empty()) {
        return false;
    }

    // We want to store in standard for "%04X:%04X" so we
    // need to extract the values or wildcards
    if ("*:*" == str) {
        m_listAllowedEvents.push_back(str);
        return true;
    }

    // Left wildcard
    if ('*' == str[0]) {
        str       = vscp_str_right(str, str.length() - 2);
        vscp_type = vscp_readStringValue(str);
        str       = vscp_str_format("*:%04X", vscp_type);
        m_listAllowedEvents.push_back(str);
        return true;
    }

    // Right wildcard
    if ('*' == str[str.length() - 1]) {
        str        = vscp_str_left(str, str.length() - 2);
        vscp_class = vscp_readStringValue(str);
        str        = vscp_str_format("%04X:*", vscp_class);
        m_listAllowedEvents.push_back(str);
        return true;
    }

    // class:type
    vscp_class = vscp_readStringValue(str);
    size_t pos;
    if (std::string::npos != (pos = str.find(':'))) {
        str       = vscp_str_right(str, str.length() - pos - 1);
        vscp_type = vscp_readStringValue(str);
        str       = vscp_str_format("%04X:%04X", vscp_class, vscp_type);
        m_listAllowedEvents.push_back(str);
        return true;
    }

    return false;
}

///////////////////////////////////////////////////////////////////////////////
// setAllowedEventsFromString
//

bool
CUserItem::setAllowedEventsFromString(const std::string& strEvents, bool bClear)
{
    std::string str;

    // Privileges
    if (strEvents.length()) {

        if (bClear) {
            m_listAllowedEvents.clear();
        }

        std::deque<std::string> tokens;
        vscp_split(tokens, strEvents, ",");

        while (!tokens.empty()) {
            str = tokens.front();
            tokens.pop_front();
            vscp_trim(str);

            addAllowedEvent(str);
        };
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// getAllowedEventsAsString
//

std::string
CUserItem::getAllowedEventsAsString(void)
{
    std::string strAllowedEvents;

    for (size_t i = 0; i < m_listAllowedEvents.size(); i++) {

        strAllowedEvents += m_listAllowedEvents[i];

        if (i != (m_listAllowedEvents.size() - 1)) {
            strAllowedEvents += "/";
        }
    }

    return strAllowedEvents;
}

///////////////////////////////////////////////////////////////////////////////
// setAllowedRemotesFromString
//

bool
CUserItem::setAllowedRemotesFromString(const std::string& strConnect)
{
    // Privileges
    if (strConnect.length()) {

        m_listAllowedRemotes.clear();

        std::deque<std::string> tokens;
        vscp_split(tokens, strConnect, ",");

        while (!tokens.empty()) {
            std::string remote = tokens.front();
            tokens.pop_front();
            vscp_trim(remote);
            addAllowedRemote(remote);
        }
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// getAllowedRemotesAsString
//

std::string
CUserItem::getAllowedRemotesAsString(void)
{
    size_t i;
    std::string strAllowedRemotes;

    for (i = 0; i < m_listAllowedRemotes.size(); i++) {

        strAllowedRemotes += m_listAllowedRemotes[i];

        if (i != (m_listAllowedRemotes.size() - 1)) {
            strAllowedRemotes += ",";
        }
    }

    return strAllowedRemotes;
}

///////////////////////////////////////////////////////////////////////////////
// getAllowedRemote
//

bool
CUserItem::getAllowedRemote(size_t n, std::string& remote)
{
    if (!m_listAllowedRemotes.size()) {
        return false;
    }

    if (n > (m_listAllowedRemotes.size() - 1)) {
        return false;
    }

    remote = m_listAllowedRemotes[n];
    return true;
}

///////////////////////////////////////////////////////////////////////////////
// setAllowedRemote
//

bool
CUserItem::setAllowedRemote(size_t n, std::string& remote)
{
    if (!m_listAllowedRemotes.size()) {
        return false;
    }

    if (n > (m_listAllowedRemotes.size() - 1)) {
        return false;
    }

    m_listAllowedRemotes[n] = remote;

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// getUserRightsAsString
//

std::string
CUserItem::getUserRightsAsString(void)
{
    std::string strRights;

    for (int i = 0; i < 32; i++) {
        strRights += vscp_str_format("%d", (m_userRights & (2 ^ i)) ? 1 : 0);
    }

    std::reverse(strRights.begin(), strRights.end());
    return strRights;
}

////////////////////////////////////////////////////////////////////////////////
// isAllowedToConnect
//
//

int
CUserItem::isAllowedToConnect(uint32_t remote_ip)
{
    int allowed = '+';
    int flag;
    uint32_t net, mask;

    remote_ip = htonl(remote_ip);

    // If the list is empty - allow all
    // if (0 == m_listAllowedRemotes.size()) return 1;

    for (size_t i = 0; i < m_listAllowedRemotes.size(); i++) {

        flag = m_listAllowedRemotes[i].at(0); // vec.ptr[0];
        if ((flag != '+' && flag != '-') ||
            (0 ==
             vscp_parse_ipv4_addr(m_listAllowedRemotes[i].substr(1).c_str(),
                                  &net,
                                  &mask))) {
            return -1;
        }

        if (net == (remote_ip & mask)) {
            allowed = flag;
        }
    }

    return ('+' == allowed) ? 1 : 0;
}

///////////////////////////////////////////////////////////////////////////////
// isUserAllowedToSendEvent
//

bool
CUserItem::isUserAllowedToSendEvent(const uint32_t vscp_class,
                                    const uint32_t vscp_type)
{
    unsigned int i;
    std::string str;

    // If empty all events allowed
    if (m_listAllowedEvents.empty()) {
        return true;
    }

    // test wildcard *.*
    str = "*:*";
    for (i = 0; i < m_listAllowedEvents.size(); i++) {
        if (m_listAllowedEvents[i] == str) {
            return true;
        }
    }

    str = vscp_str_format("%04X:%04X", vscp_class, vscp_type);
    for (i = 0; i < m_listAllowedEvents.size(); i++) {
        if (m_listAllowedEvents[i] == str) {
            return true;
        }
    }

    // test wildcard class.*
    str = vscp_str_format("%04X:*", vscp_class);
    for (i = 0; i < m_listAllowedEvents.size(); i++) {
        if (m_listAllowedEvents[i] == str) {
            return true;
        }
    }

    spdlog::error("isUserAllowedToSendEvent: Not allowed to send event - ");

    return false;
}

//*****************************************************************************
//                              CUserList
//*****************************************************************************

///////////////////////////////////////////////////////////////////////////////
// Constructor
//

CUserList::CUserList(void)
{
    // First local user except the super user has id 1
    m_cntLocaluser = 1;
}

///////////////////////////////////////////////////////////////////////////////
// Destructor
//

CUserList::~CUserList(void)
{
    {
        for (std::map<std::string, CGroupItem*>::iterator it =
               m_grouphashmap.begin();
             it != m_grouphashmap.end();
             ++it) {
            CGroupItem* pItem = it->second;
            if (NULL != pItem) {
                delete pItem;
            }
        }
    }

    m_grouphashmap.clear();

    {
        for (std::map<std::string, CUserItem*>::iterator it =
               m_userhashmap.begin();
             it != m_userhashmap.end();
             ++it) {
            CUserItem* pItem = it->second;
            if (NULL != pItem) {
                delete pItem;
            }
        }
    }

    m_userhashmap.clear();
}



///////////////////////////////////////////////////////////////////////////////
// addUser
//

bool
CUserList::addUser(const std::string& user,
                   const std::string& passwordHash,
                   const std::string& fullname,
                   const std::string& strNote,
                   const vscpEventFilter* pFilter,
                   const std::string& userRights,
                   const std::string& allowedRemotes,
                   const std::string& allowedEvents,
                   uint32_t bFlags)
{
    char buf[512];

    // Cant add user with name that is already defined.
    if (NULL != m_userhashmap[user]) {
        spdlog::error("addUser: Failed to add user - "
                      "user is already defined.");
        return false;
    }

    // // New user item
    CUserItem* pItem = new CUserItem;
    if (NULL == pItem) {
        spdlog::error("addUser: Failed to add user - "
                      "Memory problem (CUserItem).");
        return false;
    }

    pItem->setUserID(m_cntLocaluser);
    m_cntLocaluser++; // Update local user id counter

    pItem->setUserName(user);
    pItem->fixName();
    pItem->setPassword(passwordHash);
    pItem->setFullname(fullname);
    pItem->setNote(strNote);
    pItem->setFilter(pFilter);
    pItem->setUserRightsFromString(userRights);
    pItem->setAllowedRemotesFromString(allowedRemotes);
    pItem->setAllowedEventsFromString(allowedEvents);
    pItem->setFlags(bFlags);

    // Add to the map
    m_userhashmap[user] = pItem;

    // Set filter filter
    if (NULL != pFilter) {
        pItem->setFilter(pFilter);
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// addUser
//
// name;password;fullname;filter;mask;rights;remotes;events;note
//

bool
CUserList::addUser(const std::string& strUser,
                   bool bUnpackNote)
{
    std::string strToken;
    std::string user;
    std::string passwordHash;
    std::string fullname;
    std::string strNote;
    vscpEventFilter filter;
    vscp_clearVSCPFilter(&filter);
    std::string userRights;
    std::string allowedRemotes;
    std::string allowedEvents;

    std::deque<std::string> tokens;
    vscp_split(tokens, strUser, ";");

    // user
    if (!tokens.empty()) {
        user = tokens.front();
        tokens.pop_front();
    }

    // password
    if (!tokens.empty()) {
        passwordHash = tokens.front();
        tokens.pop_front();
    }

    // fullname
    if (!tokens.empty()) {
        fullname = tokens.front();
        tokens.pop_front();
    }

    // filter
    if (!tokens.empty()) {
        vscp_readFilterFromString(&filter, tokens.front());
        tokens.pop_front();
    }

    // mask
    if (!tokens.empty()) {
        vscp_readMaskFromString(&filter, tokens.front());
        tokens.pop_front();
    }

    // user rights
    if (!tokens.empty()) {
        userRights = tokens.front();
        tokens.pop_front();
    }

    // allowed remotes
    if (!tokens.empty()) {
        allowedRemotes = tokens.front();
        tokens.pop_front();
    }

    // allowed events
    if (!tokens.empty()) {
        allowedEvents = tokens.front();
        tokens.pop_front();
    }

    // note
    if (!tokens.empty()) {
        if (bUnpackNote) {
            strNote = tokens.front();
            tokens.pop_front();
            vscp_base64_std_decode(strNote);
        }
        else {
            strNote = tokens.front();
            tokens.pop_front();
        }
    }

    // flags
    uint32_t bFlags = 0;
    if (!tokens.empty()) {
        bFlags = std::stoul(tokens.front());
        tokens.pop_front();
    }

    if (!addUser(user,
                   passwordHash,
                   fullname,
                   strNote,
                   &filter,
                   userRights,
                   allowedRemotes,
                   allowedEvents,
                   bFlags)) {
        spdlog::error("addUser: Failed to add user '{}'.", user);
        return false;
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// deleteUser
//

bool
CUserList::deleteUser(const std::string& user)
{
    CUserItem* pUser = getUser(user);
    if (NULL == pUser) {
        spdlog::error("deleteUser: Failed to delete user - "
                      "User is not defined.");
        return false;
    }

    // Remove also from internal table
    m_userhashmap.erase(user);

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// deleteUser
//

bool
CUserList::deleteUser(const long userid)
{
    CUserItem* pUser = getUser(userid);
    if (NULL == pUser) {
        spdlog::error("deleteUser: Failed to delete user - "
                      "User is not defined.");
        return false;
    }

    return deleteUser(pUser->getUserName());
}

///////////////////////////////////////////////////////////////////////////////
// getUser
//

CUserItem*
CUserList::getUser(const std::string& user)
{
    return m_userhashmap[user];
}

///////////////////////////////////////////////////////////////////////////////
// getUser
//

CUserItem*
CUserList::getUser(const long userid)
{
    std::map<std::string, CUserItem*>::iterator it;
    for (it = m_userhashmap.begin(); it != m_userhashmap.end(); ++it) {
        std::string key      = it->first;
        CUserItem* pUserItem = it->second;
        if (userid == pUserItem->getUserID()) {
            return pUserItem;
        }
    }

    spdlog::error("getUser: Failed to get user - "
                  "User is not found.");

    return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// validateUser
//

CUserItem*
CUserList::validateUser(const std::string& user,
                        const std::string& passwordhash)
{
    CUserItem* pUserItem;

    pUserItem = m_userhashmap[user];
    if (NULL == pUserItem) {
        spdlog::error("validateUser: Failed to validate user - "
                      "User is not defined.");
        return NULL;
    }

    if (!pUserItem->validatePassword(passwordhash)) {
        spdlog::info("validateUser: Failed to validate user - "
                     "Check username/password.");
        return NULL;
    }

    return pUserItem;
}

///////////////////////////////////////////////////////////////////////////////
// getUserAsString
//
// userid;name;passwordhash;fullname;filter;mask;rights;remotes;events;note;flags
//

bool
CUserList::getUserAsString(CUserItem* pUserItem, std::string& strUser)
{
    std::string str;
    strUser.clear();

    // Check pointer
    if (NULL == pUserItem) {
        spdlog::error("getUserAsString: Failed to get user - "
                      "IOnvalid user item.");
        return false;
    }

    return pUserItem->getAsString(strUser);
}

///////////////////////////////////////////////////////////////////////////////
// getUserAsString
//
// userid;name;passwordhash;fullname;filter;mask;rights;remotes;events;note;flags
//

bool
CUserList::getUserAsString(uint32_t idx, std::string& strUser)
{
    std::string str;
    uint32_t i = 0;

    std::map<std::string, CUserItem*>::iterator it;
    for (it = m_userhashmap.begin(); it != m_userhashmap.end(); ++it) {

        if (i == idx) {
            std::string key      = it->first;
            CUserItem* pUserItem = it->second;
            if (getUserAsString(pUserItem, strUser)) {
                return true;
            }
            else {
                return false;
            }
        }

        i++;
    }

    return false;
}

///////////////////////////////////////////////////////////////////////////////
// getAllUsers
//
// userid;name;passwordhash;fullname;filter;mask;rights;remotes;events;note;flags
//

bool
CUserList::getAllUsers(std::string& strAllusers)
{
    std::string str;
    strAllusers.clear();

    std::map<std::string, CUserItem*>::iterator it;
    for (it = m_userhashmap.begin(); it != m_userhashmap.end(); ++it) {
        std::string key      = it->first;
        CUserItem* pUserItem = it->second;
        if (getUserAsString(pUserItem, str)) {
            strAllusers += str;
            strAllusers += "\r\n";
        }
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// getAllUsers
//

bool
CUserList::getAllUsers(std::deque<std::string>& arrayUsers)
{
    std::string str;

    std::map<std::string, CUserItem*>::iterator it;
    for (it = m_userhashmap.begin(); it != m_userhashmap.end(); ++it) {
        std::string key = it->first;
        // CUserItem* pUserItem = it->second;
        arrayUsers.push_back(key);
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// getUserItemFromOrdinal
//

CUserItem*
CUserList::getUserItemFromOrdinal(uint32_t idx)
{
    std::string str;
    uint32_t i = 0;

    std::map<std::string, CUserItem*>::iterator it;
    for (it = m_userhashmap.begin(); it != m_userhashmap.end(); ++it) {

        if (i == idx) {
            std::string key      = it->first;
            CUserItem* pUserItem = it->second;
            return pUserItem;
        }

        i++;
    }

    return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// getUserFromName
//

CUserItem*
CUserList::getUserFromName(const std::string& name)
{
    std::map<std::string, CUserItem*>::iterator it;
    it = m_userhashmap.find(name);
    if (it != m_userhashmap.end()) {
        return it->second;
    }
    return NULL;
}