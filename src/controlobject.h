// ControlObject.h: interface for the CControlObject class.
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
    @file controlobject.h
    @brief Interface for the CControlObject class.

    This file contains the definition of the CControlObject class, which
    manages the main control logic in the VSCP daemon.

    @author Ake Hedman and contributors, the VSCP project
    @date 2000-2026
    @version 1.0
    @copyright Copyright (C) 2000-2026 Ake Hedman and contributors, the VSCP
   project
    @license MIT License
*/

#if !defined(CONTROLOBJECT_H__INCLUDED_)
#define CONTROLOBJECT_H__INCLUDED_

#include "clientlist.h"
#include "devicelist.h"
#include "interfacelist.h"
#include "tcpipsrv.h"
#include "userlist.h"
#include <vscp.h>

#include <atomic>
#include <map>
#include <set>

#include <mustache.hpp>
#include <nlohmann/json.hpp> // Needs C++11  -std=c++11
#include <sqlite3.h>

#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/spdlog.h"

// https://github.com/nlohmann/json
using json = nlohmann::json;

using namespace kainjow::mustache;

// Needed on Linux
#ifndef VSCPMIN
#define VSCPMIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

#ifndef VSCPMAX
#define VSCPMAX(a, b)                                                          \
    ({                                                                         \
        __typeof__(a) _a = (a);                                                \
        __typeof__(b) _b = (b);                                                \
        _a > _b ? _a : _b;                                                     \
    })
#endif

#define VSCP_MAX_DEVICES 1024 // abs. max. is 0xffff

// Forward declarations
class TCPListenThread;

// TTL     Scope
// ----------------------------------------------------------------------
// 0       Restricted to the same host.Won't be output by any interface.
// 1       Restricted to the same subnet.Won't be forwarded by a router.
// <32     Restricted to the same site, organization or department.
// <64     Restricted to the same region.
// <128    Restricted to the same continent.
// <255    Unrestricted in scope.Global.
#define IP_MULTICAST_DEFAULT_TTL 1

// Needed on Linux
#ifndef VSCPMIN
#define VSCPMIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

#ifndef VSCPMAX
#define VSCPMAX(a, b)                                                          \
    ({                                                                         \
        __typeof__(a) _a = (a);                                                \
        __typeof__(b) _b = (b);                                                \
        _a > _b ? _a : _b;                                                     \
    })
#endif

#define MAX_ITEMS_RECEIVE_QUEUE        1021
#define MAX_ITEMS_SEND_QUEUE           1021
#define MAX_ITEMS_CLIENT_RECEIVE_QUEUE 8192

// VSCP daemon defines from vscp.h
#define VSCP_MAX_CLIENTS 4096 // abs. max. is 0xffff
#define VSCP_MAX_DEVICES 1024 // abs. max. is 0xffff

/*!
    This is the class that does the main work in the daemon.
*/

class CControlObject {
  public:
    // Will quit if set to true
    // Atomic: set from signal handler / other threads, read in main loop
    std::atomic<bool> m_bQuit;

    /*!
        Constructor
     */
    CControlObject(void);

    /*!
        Destructor
     */
    virtual ~CControlObject(void);

    /*!
        Generate a random session key from a string key
        @param pKey Null terminated string key (max 255 characters)
        @param pSid Pointer to 33 byte sid that will receive sid
     */
    bool generateSessionId(const char* pKey, char* pSid);

    /*!
        Get server capabilities (64-bit array)
        @param pCapability Pointer to 64 bit capabilities array
        @return True on success.
     */
    bool getVscpCapabilities(uint8_t* pCapability);

    /*!
        General initialisation
     */
    bool init(std::string& strcfgfile, std::string& rootFolder);

    /*!
        Clean up used resources
     */
    bool cleanup(void);

    /*!
        The main worker thread
     */
    bool run(void);

    /*!
        Start worker threads for devices
        @return true on success
     */
    bool startDeviceWorkerThreads(void);

    /*!
        Stop worker threads for devices
        @return true on success
     */
    bool stopDeviceWorkerThreads(void);

    /*!
        Starting daemon worker thread
        @return true on success
     */
    bool startDaemonWorkerThread(void);

    /*!
        Stop daemon worker thread
        @return true on success
     */
    bool stopDaemonWorkerThread(void);

    /*!
        Starting TCP/IP worker thread
        @return true on success
     */
    bool startTcpipSrvThread(void);

    /*!
        Stop the TCP/IP worker thread
        @return true on success
     */
    bool stopTcpipSrvThread(void);

    /*!
        Starting Client worker thread
        @return true on success
     */
    bool startClientMsgWorkerThread(void);

    /*!
        Stop Client worker thread
        @return true on success
     */
    bool stopClientMsgWorkerThread(void);

    /*!
        Add a new client to the client list

        @param Pointer to client that should be added.
        @param Normally not used but can be used to set a special
        client id.
        @return True on success.
    */
    bool addClient(CClientItem* pClientItem,
                   uint16_t id = CClientItem::CLIENT_ID_NONE);

    /*!
        Add a new client to the client list using GUID.

        This add client method is for drivers that specify a
        full GUID (two lsb nilled).

        @param Pointer to client that should be added.
        @param guid The guid that is used for the client. Two least
        significant bytes will be set to zero.
        @return True on success.
     */
    bool addClient(CClientItem* pClientItem, cguid& guid);

    /*!
        Add a known node
        @param guid Real GUID for node
        @param name Symbolic name for node.
    */
    void addKnownNode(cguid& guid, cguid& ifguid, std::string& name);

    /*!
        Remove a new client from the client list

        @param pClientItem Pointer to client that should be added.
     */
    //void removeClient(CClientItem* pClientItem);

    /*!
        Get device address for primary ehernet adapter

        @param guid class
     */
    bool getGuidFromMacAddress(cguid& guid);

    /*!
        Get the first IP address computer is known under and convert it to a GUID.

        @param pGUID Pointer to GUID class
     */
    bool getGuidFromIPAddress(cguid& guid);

    /*!
        Read configuration data
        @param strcfgfile path to configuration file.
        @return Returns true on success false on failure.
     */
    bool readConfiguration(const std::string& strcfgfile);

    

    /*!
     * Check if a driver name is free to us
     *
     * @param drvname Name of driver to check.
     * @return true if 'drvname' is not used
     */
    bool checkIfDriverNameFreeToUse(std::string& drvname)
    {
        return (m_driverNameSet.find("drvname") == m_driverNameSet.end());
    }

    /*!
     * Get the system key
     *
     * @param pKey Buffer that will get 32-byte key. Can be NULL in which
     *              case the key is not copied to the param.
     * @return Pointer to the 32 byte key
     */
    uint8_t* getSystemKey(uint8_t* pKey);


    /*!
     * Get MD5 of system key (vscptoken)
     *
     * @param Reference to string that will receive the MD5 of the key.
     */
    void getSystemKeyMD5(std::string& strKey);

    /*!
     * Create the folder structure that the VSCP daemon is expecting
     * https://www.vscp.org/docs/vscpd/doku.php?id=files_and_directory_structure
     */
    bool createFolderStructure(void);

    /*!
        Perform automation tasks for the given client.
        @param pClientItem Client for which to perform automation.
        @return True on success, false on failure.
    */
    bool doAutomation(CClientItem* pClientItem);

    //**************************************************************************
    //                            Getters and setters
    //**************************************************************************

    /*!
        Set the interface address for the TCP/IP connection.
        @param interfaceAddress The address of the interface.
    */
    void setInterfaceAddress(const std::string& interfaceAddress)
    {
        m_interfaceAddress = interfaceAddress;
    }

    /*!
        Get the interface address for the TCP/IP connection.
        @return The address of the interface.
    */
    std::string getInterfaceAddress() const { return m_interfaceAddress; }

    /// @brief  Get the TLS options for the TCP/IP interface.
    /// @param  None
    /// @return Reference to the TLS options structure.
    mg_tls_opts& getTlsOptions(void) { return m_tcpip_tls_opts; }


    /*!
        Get client list
        @return Reference to the map of client items.
    */
    CClientList& getClientList() { return m_clientList; };

    uint32_t getMaxItemsInClientReceiveQueue(void) const
    {
        return m_maxItemsInClientReceiveQueue;
    }

    // Get client form connection
    /*!
        Get client item from connection.
        @param connectionId The ID of the connection.
        @return Pointer to the client item, or nullptr if not found.
    */
    const CClientItem* getClientFromConnection(struct mg_connection* pConnection);

    /*!
        Add a client item to the client list.
        @param pClientItem Pointer to the client item to add.
    */
    void addClientItem(CClientItem* pClientItem);

    /*!
        Remove a client item from the client list.
        @param pClientItem Pointer to the client item to remove.
    */
    void removeClientItem(CClientItem* pClientItem);

    /*!
        Get the user list.
        @return Reference to the user list.
    */
    CUserList getUserList() { return m_userList; }

  private:
    // This is the root folder for the VSCP daemon, it will look for
    // the configuration database here
    std::string m_rootFolder;

    // Set to true of the clientWorkerThread should terminate
    bool m_bQuit_clientMsgWorkerThread;

    //**************************************************************************
    //                                 Security
    //**************************************************************************

    // Password is MD5 hash over "username:domain:password"
    std::string m_admin_user; // Defaults to "admin"
    std::string m_admin_password;
    // Default password salt;key
    // E2D453EF99FB3FCD19E67876554A8C27;A4A86F7D7E119BA3F0CD06881E371B989B33B6D606A863B633EF529D64544F8E
    std::string m_admin_allowfrom; // Remotes allowed to connect from as admin.
                                   // Defaults to ""
    std::string m_vscptoken;
    // A4A86F7D7E119BA3F0CD06881E371B989B33B6D606A863B633EF529D64544F8E
    // {
    // 0xA4,0xA8,0x6F,0x7D,0x7E,0x11,0x9B,0xA3,0xF0,0xCD,0x06,0x88,0x1E,0x37,0x1B,0x98,
    //   0x9B,0x33,0xB6,0xD6,0x06,0xA8,0x63,0xB6,0x33,0xEF,0x52,0x9D,0x64,0x54,0x4F,0x8E
    //   };
    uint8_t m_systemKey[32];

    /*!
        User to run as for Unix
        if not ""
    */
    std::string m_runAsUser;

    /*!
        Name of this server
     */
    std::string m_strServerName;

    /*!
        Server GUID
        This is the GUID for the server. The server GUID should have
        the least significant two bytes set to zero so they can be used
        for interfaces.
    */
    cguid m_guid;

    //**************************************************************************
    //                            Communication
    //**************************************************************************

    /////////////////////////////////////////////////////////
    //                      TCP/IP server
    /////////////////////////////////////////////////////////

    /*!
        Interface used for TCP/IP connection  (only one)
        Examples for IPv4: 80, 127.0.0.1:9598,
            192.0.2.3:9598,
            tcp://192.0.2.3:9599,
            ssl://192.0.2.3:9598.
            tls://192.0.2.3:9598
        Examples for IPv6: [::]:9598,
            [::1]:9598,
            tcp://[::1]:9598,
            tcp://[::1]:9598,
            ssl://[::1]:9598,
            tls://[::1]:9598
    */
    std::string m_interfaceAddress;

    /*!
        tcp/ip SSL settings

        ca - Certificate Authority, an mg_str. Used to verify the certificate
       that the other end sends to us. If NULL, then server authentication for
       clients and client authentication for servers are disabled.
       If ca is set but cert is NULL, then only server authentication is
       performed.

       cert - Our own
        certificate; an mg_str. If NULL, then we don't authenticate ourselves to
       the other peer.


       key - Our own private key; an mg_str. Sometimes, a
       certificate and its key are bundled in a single PEM file, in which case
       the values for cert and key could be the same

       name - Server name; an
       mg_str. If not empty, enable server name verification.

        NOTE: if both ca and cert are set, then two-way (mutual) TLS
       authentication is enabled, both sides authenticate each other. Usually,
       for one-way (server) TLS authentication, server connections set both key
       and cert, whilst clients only ca and/or possibly name.
    */
    mg_tls_opts m_tcpip_tls_opts;

    //**************************************************************************
    //                                DATABASE
    //**************************************************************************

    /*!
        Path to class/type definition database
    */
    std::string m_pathClassTypeDefinitionDb;

    std::map<uint16_t, std::string>
      m_map_class_id2Token; // vscp_class -> class_token
    std::map<std::string, uint16_t>
      m_map_class_token2Id; // class_token -> vscp_class

    std::map<uint32_t, std::string>
      m_map_type_id2Token; // ((vscp_class << 16) + vscp_type) -> type_token
    std::map<std::string, uint32_t>
      m_map_type_token2Id; // type_token -> ((vscp_class << 16) + vscp_type)

    /*!
    Path to discovery database
    Set empty to disable functionality
*/
    std::string m_pathMainDb;
    sqlite3* m_db_vscp_daemon;

    std::map<std::string, std::string>
      m_map_discoveryGuidToName; // key = GUID, value = name

    // Protects m_map_discoveryGuidToName, discovery db writes and discovery
    // publish. discovery() is called concurrently from all device threads.
    pthread_mutex_t m_mutex_discovery;

    //**************************************************************************
    //                            LOGGER (SPDLOG)
    //**************************************************************************

    bool m_bEnableFileLog;
    spdlog::level::level_enum m_fileLogLevel;
    std::string m_fileLogPattern;
    std::string m_path_to_log_file;
    uint32_t m_max_log_size;
    uint16_t m_max_log_files;

    bool m_bEnableConsoleLog;
    spdlog::level::level_enum m_consoleLogLevel;
    std::string m_consoleLogPattern;

    bool m_bEnableSysLog;
    spdlog::level::level_enum m_sysLogLevel;
    std::string m_sysLogIdent;

    bool m_bEnableUdpLog;
    spdlog::level::level_enum m_udpLogLevel;
    std::string m_udpLogPattern;
    std::string m_udpLogHost;
    uint16_t m_udpLogPort;

    //**************************************************************************
    //                                 DRIVERS
    //*************************************************************************

    // The list with available devices.
    CDeviceList m_deviceList;
    pthread_mutex_t m_mutex_DeviceList;

    // This set holds driver names.
    // Returns true for an active driver
    // A driver can only be loaded if it have an unique name.

    std::set<std::string> m_driverNameSet;

    std::map<std::string, CDeviceItem> m_driverNameDeviceMap;

    // Mutex for device queue
    pthread_mutex_t m_mutex_deviceList;

    // Automation Object
    //CAutomation m_automation;

    /// @brief Username for drivers (CClientItem)
    std::string m_driverUsername;

    /// @brief Password for drivers (CClientItem)
    std::string m_driverPassword;

    //**************************************************************************
    //                                CLIENTS
    //**************************************************************************

    // The list with active clients. (protecting mutex in CClientList object)
    CClientList m_clientList;

    // map connection to clientitem
    std::map<struct mg_connection*, CClientItem*> m_connectionClientItemMap;

    //**************************************************************************
    //                                USERS
    //**************************************************************************

    // The list of users allowed to connect
    CUserList m_userList; // deque
    //pthread_mutex_t m_mutex_UserList;

    // *************************************************************************
    //                      Output queue for clients
    // *************************************************************************


    /*!
        Maximum number of items in receive queue for clients (ClientBufferSize)
     */
    uint32_t m_maxItemsInClientReceiveQueue;

    

    //**************************************************************************
    //                          Threads
    //**************************************************************************

    /*!
        controlobject device thread
     */
    pthread_t m_clientMsgWorkerThread;

    /*!
        The server thread for the VSCP daemon
     */
    // daemonWorkerObj *m_pdaemonWorkerObj;
    // pthread_t m_pdaemonWorkerThread;
};

#endif // !defined(CONTROLOBJECT_H__7D80016B_5EFD_40D5_94E3_6FD9C324CC7B__INCLUDED_)
