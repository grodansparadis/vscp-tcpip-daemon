// ClientList.h: interface for the CClientList class.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP (https://www.vscp.org)
//
// Copyright (C) 2000-2026 Ake Hedman,
// Ake Hedman, the VSCP project, <info@vscp.org>
//
// This file is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this file see the file COPYING.  If not, write to
// the Free Software Foundation, 59 Temple Place - Suite 330,
// Boston, MA 02111-1307, USA.
//

/*!
    @brief Functionality for managing connected clients in the VSCP system.
    This includes handling client connections, managing input queues, and associating clients with specific interface types.
    It provides an interface for sending and receiving VSCP events, managing client sessions, and enforcing access control based on client capabilities.
    The object is owned by the application ControlObject which holds users and clients.

    The object is owned by the application ControlObject which holds users and clients
*/

#if !defined(CLIENTLIST_H__B0190EE5_E0E8_497F_92A0_A8616296AF3E__INCLUDED_)
#define CLIENTLIST_H__B0190EE5_E0E8_497F_92A0_A8616296AF3E__INCLUDED_

// Robust Windows platform detection for GitHub Actions and various build
// environments
#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) ||                \
  defined(__TOS_WIN__) || defined(__WINDOWS__)
#ifndef WIN32
#define WIN32
#endif
#ifndef _WIN32
#define _WIN32
#endif
#endif

#include <pthread.h>

#include <guid.h>
#include <userlist.h>
#include <vscp.h>
#include <vscpdatetime.h>

#include <deque>
#include <list>

/// Forward declarations for classes and structs used in CClientItem
class CControlObject;
struct mg_connection;

/*!
    @brief Client Item representing a connected client in the system.
    A client has a device name, input queue, and is associated with a specific
   interface type. The class provides methods to manage the client's connection,
   interface type, and input queue. All clients has a unique client ID and may
   have specific permissions and capabilities based on their interface type. The
   class also defines various constants and enumerations for client IDs, levels,
   and interface types. A user is always associated with a client item.
*/

class CClientItem {

  public:
    // Predefined client id's
    static const uint16_t CLIENT_ID_NONE = 0; // No client id assigned
    static const uint16_t CLIENT_ID_DAEMON_WORKER =
      0xffff;                                          // Internal daemon worker
    static const uint16_t CLIENT_ID_INTERNAL = 0xfffe; // Internal client

/*!
    Maximum default number of items in the client input queue
*/
#define CLIENT_ITEM_MAX_INPUT_QUEUE 20000

    /*!
        VSCP levels
    */
    enum CLIENT_ITEM_LEVEL { CLIENT_ITEM_LEVEL1 = 0, CLIENT_ITEM_LEVEL2 };

    /*!
        Client interface types
    */
    enum CLIENT_ITEM_INTERFACE_TYPE {
        CLIENT_ITEM_INTERFACE_TYPE_NONE = 0,
        CLIENT_ITEM_INTERFACE_TYPE_CLIENT_INTERNAL,  // 1 Daemon internal
        CLIENT_ITEM_INTERFACE_TYPE_DRIVER_LEVEL1,    // 2 Level I drivers
        CLIENT_ITEM_INTERFACE_TYPE_DRIVER_LEVEL2,    // 3 Level II drivers
        CLIENT_ITEM_INTERFACE_TYPE_DRIVER_LEVEL3,    // 4 Level III drivers
        CLIENT_ITEM_INTERFACE_TYPE_CLIENT_TCPIP,     // 5 TCP/IP interface
        CLIENT_ITEM_INTERFACE_TYPE_CLIENT_UDP,       // 6 UDP interface
        CLIENT_ITEM_INTERFACE_TYPE_CLIENT_WEB,       // 7 WEB interface
        CLIENT_ITEM_INTERFACE_TYPE_CLIENT_WEBSOCKET, // 8 Websocket interface
        CLIENT_ITEM_INTERFACE_TYPE_CLIENT_REST,      // 9 REST interface
        CLIENT_ITEM_INTERFACE_TYPE_CLIENT_MULTICAST, // 10 Multicast interface
        CLIENT_ITEM_INTERFACE_TYPE_CLIENT_MULTICAST_CH, // 11 Multicast channel
                                                        // interface
        CLIENT_ITEM_INTERFACE_TYPE_CLIENT_MQTT,         // 12 MQTT interface
        CLIENT_ITEM_INTERFACE_TYPE_CLIENT_COAP,         // 13 COAP interface
        CLIENT_ITEM_INTERFACE_TYPE_CLIENT_DISCOVERY,  // 14 Discovery interface
        CLIENT_ITEM_INTERFACE_TYPE_CLIENT_JAVASCRIPT, // 15 JavaScript interface
        CLIENT_ITEM_INTERFACE_TYPE_CLIENT_LUA,        // 16 LUA Script interface
    };

  public:
    /// Constructor
    CClientItem();
    CClientItem(CControlObject* pControl,
                CLIENT_ITEM_INTERFACE_TYPE type,
                struct mg_connection* conn);

    /// Destructor
    ~CClientItem();

  public:
    // Getters/Setters

    /*!
        Set device name
        @param name Name to set
    */
    void setDeviceName(const std::string& name);

    /*!
        Get device name
    */
    std::string getDeviceName(void) { return m_strDeviceName; };

    /// Clear input queue
    void clearClientInputQueue(void);

    /// @brief Get the size of the client input queue
    /// @param  None
    /// @return Size of the client input queue
    size_t getClientInputQueueSize(void);

    /*!
        Wait for an event to be added to the client input queue.
        @param timeoutMs Maximum time to wait in milliseconds
        @return 0 when signaled, -1 on timeout or error
    */
    int waitForInputQueueEvent(uint32_t timeoutMs);

    /*!
        Get event from the client input queue
        @param bRemove Flag indicating whether to remove the event from the
       queue
        @return Event from the client input queue, or NULL if the queue is empty
    */
    vscpEvent* getEventFromClientInputQueue(bool bRemove);

    /*!
        Get client on string form
        "id,type,GUID,name,dt-created(UTC),open-flag"
        @return Client info on string form
    */
    std::string getClientItemAsString(void);

    /*!
        Add an event to the input queue
        @param pEvent Event to add
        @return True if the event was successfully added, false otherwise
    */
    bool addEventToInputQueue(vscpEvent* pEvent);

    /*!
    Get event from the input queue
        @return Event from the input queue, or NULL if the queue is empty
    */
    vscpEvent* getEventFromInputQueue(void);

    /*!
        Clear the input queue of all events
        @return None
    */

    void clearInputQueue(void);

    /*!
        Check if the client is connected.
        @return true if connected, else false.
    */
    bool isConnected(void);

    // **************************************************************************
    //                         Getters and setters
    // **************************************************************************

    /// Set control object
    void setControlObject(CControlObject* pCtrlObj) { m_pCtrlObj = pCtrlObj; };

    /// Get control object
    CControlObject* getControlObject(void) { return m_pCtrlObj; };

    /*!
        Set the client ID
        @param id Client ID to set
    */
    void setClientID(uint16_t id) { m_clientID = id; };

    /*!
        Get the client ID
        @return Client ID
    */
    uint16_t getClientID(void) { return m_clientID; };

    /*!
        Get user item
        @return User item
    */
    CUserItem* getUserItem(void) { return m_pUserItem; };

    /*!
        Set user item
        @param pUserItem User item to set
    */
    void setUserItem(CUserItem* pUserItem) { m_pUserItem = pUserItem; };

    /*!
      Get filter for VSCP events
      @return Filter for VSCP events
    */
    vscpEventFilter& getFilter(void) { return m_filter; };

    /*!
      Set filter for VSCP events
      @param filter Filter to set
    */
    void setFilter(const vscpEventFilter& filter) { m_filter = filter; };

    /*!
        Set the interface type
        @param type Interface type to set
    */
    void setInterfaceType(CLIENT_ITEM_INTERFACE_TYPE type) { m_type = type; };

    /*!
        Get the interface type
        @return Interface type
    */
    CLIENT_ITEM_INTERFACE_TYPE getInterfaceType(void) { return m_type; };

    /// Set client flags
    void setFlags(uint32_t flags) { m_flags = flags; };

    /// Get client flags
    uint32_t getFlags(void) { return m_flags; };

    /// Set the maximum number of events in the client input queue (zero means
    /// unlimited)
    void setMaxItemsInClientInputQueue(uint32_t maxItems)
    {
        m_maxItemsInClientInputQueue = maxItems;
    };

    /// Get the maximum number of events in the client input queue
    uint32_t getMaxItemsInClientInputQueue(void)
    {
        return m_maxItemsInClientInputQueue;
    };

    /*!
        Set the interface GUID
        @param guid Interface GUID to set
    */
    void setInterfaceGUID(const cguid& guid) { m_guid = guid; };

    /*!
        Get the interface GUID
        @return Interface GUID
    */
    cguid getInterfaceGUID(void) { return m_guid; };

    /*! Set connection
        @param conn Mongoose connection struct pointer ()
    */
    void setConnection(struct mg_connection* conn) { m_conn = conn; };

    /// get connection
    const struct mg_connection* getConnection(void) const { return m_conn; };

    /// Set open state
    void setOpen(bool open) { m_bOpen = open; };

    /// Get open state
    bool isOpen(void) { return m_bOpen; };

    

    /*!
        Get the date and time when the client was started
        @return Date and time when the client was started
    */
    vscpdatetime getDateTimeStarted(void) { return m_dtutc; };

    /*!
        Set the date and time when the client was started to the current UTC
       time
    */
    void setDateTimeStartedNow(void) { m_dtutc.setUTCNow(); };

    /*!
        Get the session ID for this client
        @return Session ID
    */
    std::string getSessionId(void) { return std::string(m_sid); };

    // Clear session id
    void clearSessionId(void) { memset(m_sid, 0, sizeof(m_sid)); };

    /// Get status (reference)
    canalStatus& getStatus(void) { return m_status; };

    /// Set status
    void setStatus(canalStatus status) { m_status = status; };

    /// Get statistics (reference)
    canalStatistics& getStatistics(void) { return m_statistics; };

    /// Set statistics
    void setStatistics(canalStatistics statistics)
    {
        m_statistics = statistics;
    };

    /// Get the time when the receive loop was last active
    time_t getReceiveLoopTimestamp(void) { return m_timeRcvLoop; };

    /// Set the time when the receive loop was last active
    void setReceiveLoopTimestamp(time_t timestamp)
    {
        m_timeRcvLoop = timestamp;
    };

    /// Set connected status
    void setConnected(bool connected) { m_bConnected = connected; };



  private:
    /// Pointer to control object
    CControlObject* m_pCtrlObj;

    // **************************************************************************
    //                            Input queue
    // **************************************************************************

    /*!
        Input Queue (events directed TO this client)
        This queue holds events that are directed to this specific client.
       Events are added to this queue by the server and processed by the client
       as they are received.
    */
    std::deque<vscpEvent*> m_clientInputQueue;

    // Semaphore to signal that an event has been received
#ifdef WIN32
    HANDLE m_semClientInputQueue;
#else
    sem_t m_semClientInputQueue;
#endif

    // Mutex handle that is used for sharing of the client object
    pthread_mutex_t m_mutexClientInputQueue;

    /*!
      Maximum number of events allowed in input queue.
      Set to zero for no limit
    */
    uint32_t m_maxItemsInClientInputQueue;

    // --------------------------------------------------------------------------

    /*!
        Channel is open if set to true
        This is used to indicate if the client channel is currently open and
       available for communication. Open is NOT the same as being connected.
    */
    bool m_bOpen;

    /// Interface type: CANAL, TCP/IP
    CLIENT_ITEM_INTERFACE_TYPE m_type;

    /// @brief Mongoose connection struct pointer for this client
    struct mg_connection* m_conn;

    /// @brief Indicates if the client is currently connected.
    bool m_bConnected;

    /// Client ID for this client item
    uint16_t m_clientID;

    /// Client flags
    uint32_t m_flags;

    /// Filter/mask for VSCP
    vscpEventFilter m_filter;

    /*!
        Interface GUID

        The GUID for a client have the following form MSB -> LSB

        0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFD ip-address ip-address ip-address
        ip-address Client-ID Client-ID 0 0

        ip-address ver 4 interface IP address
        Client-ID mapped id for this client

        This is the default address and it can be changed by the client
       application

    */
    cguid m_guid;

    /// Interface name
    std::string m_strDeviceName;

    /// Datetime UTC when created
    vscpdatetime m_dtutc;

    /// Channel state information
    canalStatus m_status;

    /// Channel statistics
    canalStatistics m_statistics;

    /// Event to indicate that there is an event to send
#ifdef WIN32
    HANDLE m_hEventSend;
#else
    sem_t m_hEventSend;
#endif

    /*!
        Pointer to arbitrary user data object
    */
    void* m_pdata;

    ///////////////////////////////////////////////////////////////////////////
    ///                       Used by TCP/IP client thread
    //////////////////////////////////////////////////////////////////////////

    /// UTC time since last client activity
    long m_clientActivity;

    /// RCVLOOP clock (UTC time for last sent "+OK")
    time_t m_timeRcvLoop;

    /// Session id
    char m_sid[33];

    /*!
        Pointer to the logged-in user
        This pointer is set when a username is entered. It is removed if the
       authentication fails. If authentication is successfull the pointer
       remains valid until client logges out or clodes connection.
    */
    CUserItem* m_pUserItem;

    
};

// ----------------------------------------------------------------------------

/*!
    @brief Client list class representing a collection of connected clients in
   the system.

    The CClientList class provides methods to add, remove, and retrieve clients
    based on their ID, ordinal, or GUID. It also allows querying the current
    number of connected clients and retrieving all interfaces as a string.
*/

class CClientList {

  public:
    /// Constructor
    CClientList();

    /// Destructor
    virtual ~CClientList();

    /*!
        Find a free client id
        pid Pointer to uint16_t that return free id.
        @return True if id could be found
    */
    bool findFreeId(uint16_t* pid);

    /*!
        Add a client to the list
        @param pClientItem Client to add
        @param id Normally not used but can be used to set a specific id
        @return true om success.
    */
    bool addClient(CClientItem* pClientItem, uint32_t id = 0);

    /*!
        Add a client to the list using set GUID
        @param pClientItem Client to add
        @param guid The guid that is used for the client. Two least
        significant bytes will be set to zero.
        @return true om success.
    */
    bool addClient(CClientItem* pClientItem, cguid& guid);

    /*!
        Remove a client from the list
        @param pClientItem Pointer to client item
        @return true on success
    */
    bool removeClient(CClientItem* pClientItem);

    /*!
        Remove all clinets
        @return true on success
    */
    bool removeAllClients(void);

    /*!
        Get client form client id
        @param id Numeric id for the client
        @return A pointer to a clientitem on success or NULL on failure.
    */
    const CClientItem* getClientFromId(uint16_t id);

    /*!
        Get client form ordinal
        @param id Numeric ordinal for the client
        @return A pointer to a clientitem on success or NULL on failure.
    */
    const CClientItem* getClientFromOrdinal(uint16_t ordinal);

    /*!
        Get Client from GUID
        @param guid Guid for the client
        @return A pointer to a cientitem on success or NULL on failure.
    */
    const CClientItem* getClientFromGUID(cguid& guid);

    /*!
        Get client item from connection.
        @param connectionId The ID of the connection.
        @return Pointer to the client item, or nullptr if not found.
    */
    const CClientItem* getClientFromConnection(const struct mg_connection* pConnection);

    /*!
        Get current number of clients

        @return Current number of client.
    */
    size_t getClientCount(void) { return m_itemList.size(); };

    /*!
        Get all interfaces as string
        @return List of all interfaces
    */
    std::string getAllClientsAsString(void);

    /*!
        Get a client from it's ordinal
        @param n Ordinal for client in list
        @param client [out] Client data on string form
        @return true on success
    */
    bool getClient(uint16_t n, std::string& client);

    /*!
      Send event to client
      @param pClientItem Pointer to clientitem that should receive event.
      @param pEvent Event that should be sent.
      @return True on success, false on failure.
    */
    bool sendEventToClient(CClientItem* pClientItem, const vscpEvent* pEvent);

    /*!
      Send event to all clients
      @param VSCP event to send
      @param excludeID Event with this obid will be excluded. Set to zero
          if all events should be sent.
      @return true on success, false on failure
    */
    bool sendEventAllClients(const vscpEvent* pEvent, uint32_t excludeID = 0);

    /*!
        Add an event to the client output queue if capacity is available.
        @param pEvent Event to enqueue; ownership transfers on success
        @param maxSize Maximum queue size; zero prevents enqueueing
        @return True if the event was queued
    */
    bool enqueueReceiveEvent(vscpEvent* pEvent, size_t maxSize);

    /// Get the client output queue size.
    size_t getOutputQueueSize(void);

    /*!
        Get an event from the client output queue.
        @param remove Remove the event from the queue when true
        @return Queue-front event, or nullptr if the queue is empty
    */
    vscpEvent* getEventFromOutputQueue(bool remove);

    /// Wait for an event on the client output queue.
    int waitForOutputQueueEvent(uint32_t timeoutMs);

    /// Signal that the client output queue should be processed.
    void notifyOutputQueueEvent(void);

    /*!
        Get the size of the client list
        @return Number of clients in the list
    */
    size_t size(void) { return m_itemList.size(); }

    /*!
        Clear the client output queue.
    */
    void clearOutputQueue(void);

    /*!
        lock mutex for the client main receive queue.
    */
    void lockClientMainReceiveQueue(void);

    /*!
        Unlock mutex for the client main receive queue.
    */
    void unlockClientMainReceiveQueue(void);

    /*!
        waitEventInMainReceiveQueue

        @param timeoutMs Maximum time to wait for an event in milliseconds. 
        @return True if there is an event waiting in the main receive queue,
       false otherwise (timeout or error).
    */
    bool waitEventInMainReceiveQueue(uint32_t timeoutMs);

  private:
    // *********************************************************************
    //                         CLIENT OUTPUT QUEUE
    // *********************************************************************

    /*!
       Semaphore that indicates that there is an event in the client main
       receive queue.
     */
#ifdef WIN32
    HANDLE m_semClientMainReceiveQueue;
#else
    sem_t m_semClientMainReceiveQueue;
#endif

    /*!
        Mutex for the client main receive queue
     */
    pthread_mutex_t m_mutex_ClientMainReceiveQueue;

    /*!
        Semaphore that is signaled when workerthread
        have send an incoming event that should go to
        all clients
    */
    sem_t m_semSentToAllClients;

    /*!
        Receive queue

        All events received by clients are placed in this queue before being
        processed. Events are consumed by the server but also they are
        distributed to the appropriate clients.
     */
    std::deque<vscpEvent*> m_clientMainReceiveQueue;

    // *********************************************************************
    //                         CLIENT ITEM LIST
    // *********************************************************************

    // List with clients
    std::deque<CClientItem*> m_itemList;

    // Mutex that protect the list
    pthread_mutex_t m_mutexClientItemList;
};

#endif // !defined(CLIENTLIST_H__B0190EE5_E0E8_497F_92A0_A8616296AF3E__INCLUDED_)
