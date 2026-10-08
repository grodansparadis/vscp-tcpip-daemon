// userlist.h
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

/*!
    @brief Functionality for user handling and authentication
    This includes managing user rights, authentication, and group memberships.
    It provides an interface for adding, removing, and modifying users and groups.
    It also handles password hashing and verification for secure authentication.
    It ensures that only authorized users can perform specific actions based on their assigned rights.
    It defines default rights for different user roles such as admin, user, and driver.

    The object is owned by the application ControlObject which holds users and clients
*/

#if !defined(USERLIST__INCLUDED_)
#define USERLIST__INCLUDED_

#include <sodium.h>

#include <vscp.h>
#include <vscphelper.h>

#include <iostream>
#include <map>

// User rights bit array
// "admin" has all rights.
// "user" standard user rights
// "driver" can send and receive events and log in to tcp/ip through local

// Rights nibble 7
#define VSCP_USER_RIGHT_ALLOW_SHUTDOWN  0x80000000
#define VSCP_USER_RIGHT_ALLOW_RESTART   0x40000000
#define VSCP_USER_RIGHT_ALLOW_INTERFACE 0x20000000
#define VSCP_USER_RIGHT_ALLOW_TEST      0x10000000

// Rights nibble 6
#define VSCP_USER_RIGHT_ALLOW_SETGUID   0x08000000
#define VSCP_USER_RIGHT_ALLOW_SETFILTER 0x04000000

// Rights nibble 5

// Rights nibble 4

// Rights nibble 3
#define VSCP_USER_RIGHT_ALLOW_RCV_EVENT 0x00100000 // Allowed to receive

// Rights nibble 2
#define VSCP_USER_RIGHT_ALLOW_SEND_EVENT 0x00010000 // Allowed to send events
#define VSCP_USER_RIGHT_ALLOW_SEND_L1CTRL_EVENT                                \
    0x00020000 // Allowed to send Level I protocol events
#define VSCP_USER_RIGHT_ALLOW_SEND_L2CTRL_EVENT                                \
    0x00040000 // Allowed to send Level 2 protocol events
#define VSCP_USER_RIGHT_ALLOW_SEND_HLO_EVENT                                   \
    0x00040000 // Allowed to send HLO event(s)

// Rights nibble 1

// Rights nibble 0 - Low nibble is priority. Higher
// value allow for more restricted use of commands/functionality
#define VSCP_USER_RIGHT_ALLOW_TCPIP     0x00000010
#define VSCP_USER_RIGHT_ALLOW_WEBSOCKET 0x00000020
#define VSCP_USER_RIGHT_ALLOW_WEB       0x00000040

// Default user privilege
#define VSCP_ADMIN_DEFAULT_RIGHTS 0xFFFFFFFF

#define VSCP_USER_DEFAULT_RIGHTS                                               \
    VSCP_USER_RIGHT_ALLOW_TCPIP | VSCP_USER_RIGHT_ALLOW_WEBSOCKET |            \
      VSCP_USER_RIGHT_ALLOW_WEB | VSCP_USER_RIGHT_ALLOW_SEND_EVENT |           \
      VSCP_USER_RIGHT_ALLOW_RCV_EVENT |                                        \
      VSCP_USER_RIGHT_ALLOW_SEND_L1CTRL_EVENT |                                \
      VSCP_USER_RIGHT_ALLOW_SEND_L2CTRL_EVENT

#define VSCP_DRIVER_DEFAULT_RIGHTS                                             \
    VSCP_USER_RIGHT_ALLOW_TCPIP | VSCP_USER_RIGHT_ALLOW_WEBSOCKET |            \
      VSCP_USER_RIGHT_ALLOW_WEB | VSCP_USER_RIGHT_ALLOW_SEND_EVENT |           \
      VSCP_USER_RIGHT_ALLOW_RCV_EVENT |                                        \
      VSCP_USER_RIGHT_ALLOW_SEND_L1CTRL_EVENT |                                \
      VSCP_USER_RIGHT_ALLOW_SEND_L2CTRL_EVENT |                                \
      VSCP_USER_RIGHT_ALLOW_SEND_HLO_EVENT

#define VSCP_ADD_USER_UNINITIALISED -1

#define USER_PRIVILEGE_MASK  0x0f
#define USER_PRIVILEGE_BYTES 8

#define USER_ID_ADMIN 0x00 // The one and only admin user

class CGroupItem {

  public:
    /// Constructor
    CGroupItem(void);

    /// Destructor
    virtual ~CGroupItem(void);

  private:
};


/*!
    @brief User item class representing a user in the system.
    A user has a username, password, full name, notes, allowed remotes, allowed events, and user rights.
*/

class CUserItem {

  public:
    /// Constructor
    CUserItem(void);

    /// Destructor
    virtual ~CUserItem(void);

    /*!
     *  Make sure user name is a valid name
     */
    void fixName(void);

    /*!
        Validate password

        This function checks if the provided password hash matches the client's
       stored password hash. Argon2 is used.
        @param password_hash Password hash to validate
        @return True if the password is valid, false otherwise
    */
    bool validatePassword(const std::string& password_hash);

    /*
        IP ACL. By default, empty or non defined, meaning all IPs are allowed to
        connect.

        An Access Control List (ACL) allows restrictions to be put on the list
        of IP addresses which have access to the web server. The ACL is a comma
        separated list of IP subnets, where each subnet is pre-pended by either
        a - or a + sign. A plus sign means allow, where a minus sign means deny.
        If a subnet mask is omitted, such as -1.2.3.4, this means to deny only
        that single IP address.

        Subnet masks may vary from 0 to 32, inclusive. The default setting is to
        allow all accesses. On each request the full list is traversed, and the
        last match wins. Examples:

        "-0.0.0.0/0,+192.168/16" deny all accesses, only allow 192.168/16 subnet

        Verify given socket address against the ACL.

        @param remote_ip Remote ip address on network order.
        @return -1 if ACL is malformed, 0 if address is disallowed, 1 if
                allowed.

     */
    int isAllowedToConnect(uint32_t remote_ip);

    /*!
        Check if use is allowed to send event.
        First check "*.*"
        Next check "class:type"
        Next check "class:*"
        @param vscp_class VSCP class to test.
        @param vscp_type VSCP type to test.
        @return true if the client is allowed to send event.
    */
    bool isUserAllowedToSendEvent(const uint32_t vscp_class,
                                  const uint32_t vscp_type);

    /*!
        Check if user has a specific right
        @param right Right to check
        @return true if user has the right, false otherwise
    */
    bool isUserAllowed(uint64_t right)
    {
        return (m_userRights & right) == right;
    };

    /*!
     * Set user rights from a comma separated string. The string can have
     * up to eight comma separated bit field octets.
     *
     * As an alternative one can use mnemonics
     *
     * admin    - user get full access.
     * user     - user get standard user rights.
     * driver   - user get standard driver rights.
     */
    bool setUserRightsFromString(const std::string& strRights);

    /*!
     * Set allowed remote addresses for string
     * Comma separated list if IP v4 or IP v6 addresses. Wildcards can be used
     * on any position ('*').
     */
    bool setAllowedRemotesFromString(const std::string& strConnect);

    /*!
     * Save record to database
     * @return true on success.
     */
    bool saveToDatabase(void);

    /*!
     * Read record to database
     * @return true on success.
     */
    bool readBackIndexFromDatabase(void);

    /*!
     * Check if a user is with a specific userid is available in the db
     * @param userid userid to look for
     * @return true on success
     */
    static bool isUserInDB(const unsigned long userid);

    /*!
     * Check if a user is with a specific username is available in the db
     * @param user username to look for.
     * @param pid  Optional Pointer to integer that receives id for the record
     * if the user is found.
     * @return true on success
     */
    static bool isUserInDB(const std::string& user, long* pid = NULL);

    /*!
        Check password for user
        @param password Password to check
        @return true If password is correct
    */
    bool checkPassword(const std::string& password)
    {
        return (getPassword() == password);
    };


    // * * * Getters/Setters * * *

    // UserID
    long getUserID(void) { return m_userID; };
    void setUserID(const long id) { m_userID = id; };

    // Username
    std::string getUserName(void) { return m_username; };
    void setUserName(const std::string& strUser) { m_username = strUser; };

    // Password
    std::string getPassword(void) { return m_passwordhash; };
    void setPassword(const std::string& strPasswordhash)
    {
        m_passwordhash = strPasswordhash;
    };

    // Full name
    std::string getFullname(void) { return m_fullname; };
    void setFullname(const std::string& strUser) { m_fullname = strUser; };

    // Note
    std::string getNote(void) { return m_note; };
    void setNote(const std::string& note) { m_note = note; };

    // User rights
    uint32_t getUserRights(void) { return m_userRights; };

    void setUserRights(const uint32_t rights) { m_userRights = rights; };
    std::string getUserRightsAsString(void);

    // --------------------------------
    // * * * Allowed events list * * *
    // --------------------------------

    /*!
        Clear the allowed event list
    */
    void clearAllowedEventList(void) { m_listAllowedEvents.clear(); };

    /*!
        Add one allowed event
        @param strEvent Event to add on the form "class:type" where
        any of class/type can be a wildcard '*'
    */
    bool addAllowedEvent(const std::string& strEvent);

    /*!
        Get allowed event

        @param n Ordinal for event.
        @param event [out] Allowed event
        @return True on success, false on failure
    */
    bool getAllowedEvent(size_t n, std::string& event);

    /*!
        Set allowed event

        @param n Ordinal for event.
        @param event Allowed event if success.
        @return True on success, false on failure
    */
    bool setAllowedEvent(size_t n, std::string& event);

    /*!
        Get all allowed events as a comma separated string
    */
    std::string getAllowedEventsAsString(void);

    /*!
     * Set allowed event for string.
     * @param strEvents Comma separated string where each item is "class:type"
     * where either class or type or both can be a wildcard '*'
     * @param bClear If true clear the list before adding new entries.
     * @return true on succes, false otherwise
     */
    bool setAllowedEventsFromString(const std::string& strEvents,
                                    bool bClear = true);

    /*!
        Get Number of allowed events a user can send. Zero events returned means
       user can send any event.
        @return Number of events
    */
    size_t getAllowedEventsCount(void) { return m_listAllowedEvents.size(); };

    // -----------------------
    // * * * Remote list * * *
    // -----------------------

    /*!
        Return total number of allowed hosts. An empty list means
       all remote hosts can connect.
        @return Number of allowed hosts
    */
    size_t getAllowedRemotesCount(void)
    {
        return (m_listAllowedRemotes.size());
    };

    /*!
        Clear allowed hosts list. An empty list means
       all remote hosts can connect.
    */
    void clearAllowedRemoteList(void) { m_listAllowedRemotes.clear(); };

    /*!
        Add allowed remote
        @param strRemote Address (ip.v4/ip.v6) for remote host to add
    */
    void addAllowedRemote(const std::string& strRemote)
    {
        m_listAllowedRemotes.push_back(strRemote);
    };

    /*!
        Get all allowed remotes as a comma separated string. An empty list means
       all remote hosts can connect.
        @return Return list of allowed remotes as a comma separated list of
       strings.
    */
    std::string getAllowedRemotesAsString(void);

    /*!
        Get specific remote host item
        @param n Item index
        @param remote [out] Remote host on success
        @return true on success
    */
    bool getAllowedRemote(size_t n, std::string& remote);

    /*!
        Set specific remote host item
        @param n Item index
        @param remote Remote host to set
        @return true on success
    */
    bool setAllowedRemote(size_t n, std::string& remote);

    /*!
        Get receive filter
    */
    const vscpEventFilter* getUserFilter(void) { return &m_filterVSCP; };

    /*!
        Set receive filter
    */
    void setFilter(const vscpEventFilter* pFilter)
    {
        if (NULL != pFilter) {
            m_filterVSCP = *pFilter;
        }
    };

    /*!
        Set receive filter from string
    */
    bool setFilterFromString(const std::string& strFilter)
    {
        return vscp_readFilterFromString(&m_filterVSCP, strFilter);
    };

    /*!
        Set receive mask from string
    */
    bool setMaskFromString(const std::string& strMask)
    {
        return vscp_readMaskFromString(&m_filterVSCP, strMask);
    };

    std::string getFilter(void)
    {
        std::string str;
        vscp_writeFilterToString(str, &m_filterVSCP);
        return str;
    };

    std::string getMask(void)
    {
        std::string str;
        vscp_writeMaskToString(str, &m_filterVSCP);
        return str;
    };

    /*!
     * Set user settings from string
     * @param userSettings User settings in a semicolon separated list in the
     * form. leave fields blank if they should not be updated.
     * @return true on success, false on failure.
     */
    bool setFromString(const std::string& userSettings);

    /*!
     * Get user settings as string
     * @param strUser String that will get user settings
     * @return true on success, false on failure.
     */
    bool getAsString(std::string& strUser);

    /*!
     * Get user settings as map with key/value pairs
     * @param mapUser map that will get user settings as
     * key/value pairs
     * @return true on success, false on failure.
     */
    bool getAsMap(std::map<std::string, std::string>& mapUser);

    /*!
        Set flags associated with the user
        @param flags Flags to set for the user
    */
    void setFlags(uint32_t flags)
    {
        m_flags = flags;
    };

    /*!
        Get flags associated with the user
        @return Flags of the user
    */
    uint32_t getFlags(void) { return m_flags; };

  protected:
    // System assigned ID for user (-1 -  for system users (not in DB), 0 for
    // admin user )
    long m_userID;

    /// Username
    std::string m_username;

    /// Password
    std::string m_passwordhash;

    /// Full name
    std::string m_fullname;

    /// note
    std::string m_note;

    /*!
        Bit array (64-bits) with user rights i.e. tells what
        this user is allowed to do.
    */
    uint64_t m_userRights;

    /*!
        This list holds allowed events that user can send.
        Wildcards can be used and the default is all events
        allowed. Form is class:type where either or both of
        class and type can use wildcard '*'
    */
    std::deque<std::string> m_listAllowedEvents;

    /*!
        This list holds ip-addresses for remote
        computers that are allowed to connect to this
        machine. ip.v4 and ip.v6 on standard form.
    */
    std::deque<std::string> m_listAllowedRemotes;

    /*!
        Filter associated with this user
    */
    vscpEventFilter m_filterVSCP;

    /*!
        Flags associated with the user
    */
    uint32_t m_flags;
};

/*!
    @brief User list class representing a collection of users in the system.

    The CUserList class provides methods to load users from the database,
    add super users, and add regular users to the in-memory list. Changes
    must be persisted to the database to be permanent.
*/


class CUserList {
  public:
    /// Constructor
    CUserList(void);

    /// Destructor
    virtual ~CUserList(void);

    CUserList(const CUserList&) = delete;
    CUserList& operator=(const CUserList&) = delete;

    /*!
     * Load users from database
     * @return true on success
     */
    bool loadUsers(void);

    /*!
        Add a user to the in memory list. Must saved to database to make
       persistent. The configuration set username is not a valid username.
        @param user Username for user.
        @param passwordHash Password.
        @param fullname Fullname for user.
        @param strNote An arbitrary note about the user
        @param Pointer to a VSCP filter associated with this user.
        @param userRights list with user rights on the form
       right1,right2,right3.... admin - all rights user - standard user rights
                    or an unsigned long value
        @param allowedRemotes List with remote computers that are allowed to
       connect. Empty list is no restrictions.
        @param allowedEvents List with allowed events that a remote user is
       allowed to send.
        @param bFlags Flags associated with the user.
        @return true on success. false on failure.
    */
    bool addUser(const std::string& user,
                 const std::string& passwordHash,
                 const std::string& fullname,
                 const std::string& strNote,
                 const vscpEventFilter* pFilter    = NULL,
                 const std::string& userRights     = "",
                 const std::string& allowedRemotes = "",
                 const std::string& allowedEvents  = "",
                 uint32_t bFlags                   = 0);

    /*!
     * Add user from comma separated string data
     * @param strUser Comma separated list with user information.
     *      name;password;fullname;filtermask;rights;remotes;events;note
     * @return true on success. false on failure.
     */
    bool addUser(const std::string& strUser,
                 bool bUnpackNote = false);

    /*!
     * Delete a user given it's username.
     * Only non-system users can be deleted.
     * @param user Username for user to delete
     * @param true on success. false on failure.
     */
    bool deleteUser(const std::string& user);

    /*!
     * Delete a user given it's userid.
     * Only non-system users can be deleted.
     * @param userid Userid for user to delete
     * @param true on success. false on failure.
     */
    bool deleteUser(const long userid);

    /*!
        Get user
        @param user Username
        @return Pointer to user if available else NULL
    */
    CUserItem* getUser(const std::string& user);

    /*!
        Get user
        @param luserid Index for user in database.
                link_to_user == 0 is admin user
                -1 == unknown user
        @return Pointer to user if available else NULL
    */
    CUserItem* getUser(const long userid);

    /*!
        Validate a username/password pair
        @param user Username to test.
        @param passwordHash Password hash to test
        @return Pointer to useritem if valid, NULL if not.
    */
    CUserItem* validateUser(const std::string& user,
                            const std::string& passwordHash);


    /*!
     * Get number of users on the system
     * @return number of users.
     */
    uint32_t getUserCount(void) { return m_userhashmap.size(); };

    /*!
     * Get user info as string
     * Format is:
     *   userid;name;password;fullname;filter;mask;rights;remotes;events;note
     *   note is always BINHEX64 coded.
     * @param pUserItem Pointer to user.
     * @param strUser String that will receive information
     * @return true on success.
     */
    bool getUserAsString(CUserItem* pUserItem, std::string& strUser);

    /*!
     * Get user information on string form from user index
     * @param idx Index to user in storage array.
     * @param strUser String that will receive information
     * @return true on success.
     */
    bool getUserAsString(uint32_t idx, std::string& strUser);

    /*!
     * Fetch all users in semicolon separated string form ready for transfer.
     *
     * Format is:
     *   userid;name;password;fullname;filter;mask;rights;remotes;events;note
     *   note is always BINHEX64 coded.
     *
     * @param  strAllUser String containing user records in string form.
     */
    bool getAllUsers(std::string& strAllusers);

    /*!
     * Fetch all users into a string array
     * @param arrayUsers Am array with all usernames
     * @return true on success.
     */
    bool getAllUsers(std::deque<std::string>& arrayUsers);

    /*!
     * Get user item from ordinal in user array
     * @param idx Index into user array.
     * @return A pointer to the useritem at that position or NULL if no item is
     *          at that position.
     */
    CUserItem* getUserItemFromOrdinal(uint32_t idx);

    /*!
     * Get user item from username
     * @param name Username of the user.
     * @return A pointer to the useritem with the given username or NULL if no
     * such user exists.
     */
    CUserItem* getUserFromName(const std::string& name);

  protected:
    /*!
        hash with user items
    */
    std::map<std::string, CUserItem*> m_userhashmap;

    /*!
        hash with group items
    */
    std::map<std::string, CGroupItem*> m_grouphashmap;

  private:
    unsigned short m_cntLocaluser; // Counter for local user id's
};

#endif
