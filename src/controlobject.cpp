// ControlObject.cpp: m_path_db_vscp_logimplementation of the CControlObject
// class.
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
//

#define _POSIX

#include <controlobject.h>

#include <arpa/inet.h>
#include <errno.h>
#ifdef __linux__
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#endif
#include <net/if.h>
#include <net/if_arp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/msg.h>
#endif
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef WIN32
#include <nb30.h>
#endif
#ifdef WITH_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include <algorithm>
#include <deque>
#include <fstream>
#include <list>
#include <map>
#include <set>
#include <string>

#include "version.h"

extern "C" {
#include "mongoose.h"
}

#include <sodium.h>

#include <nlohmann/json.hpp>

#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/udp_sink.h"
#include "spdlog/spdlog.h"
#ifdef __linux__
#include "spdlog/sinks/syslog_sink.h"
#include <syslog.h> // for LOG_PID, LOG_USER, etc.
#endif

#include <vscp-aes.h>

#include <canal-macro.h>
#include <configfile.h>
#include <crc.h>
#include <devicelist.h>
#include <devicethread.h>
#include <guid.h>
#include <randpassword.h>
#include <vscp.h>
#include <vscpd_caps.h>
#include <vscpdb.h>
#include <vscphelper.h>
#include <vscpmd5.h>

#define UNUSED(x) (void)(x)
void
foo(const int i)
{
    UNUSED(i);
}

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

using json = nlohmann::json;

// Prototypes
void
createFolderStuct(std::string& rootFolder); // from vscpd.cpp

void*
clientMsgWorkerThread(void* userdata); // this

void*
tcpipWorkerThread(void* pdata); // tcpipsrv.cpp

// static void
// tcpip_event_handler(struct mg_connection* conn, int ev, void* ev_data);

///////////////////////////////////////////////////////////////////////////////
// log_to_spdlog
//

static void
log_to_spdlog(char ch, void* param)
{
    (void)param;
    static thread_local std::string line;

    if (ch != '\n') {
        line.push_back(ch);
        return;
    }

    if (!line.empty() && line.back() == '\r')
        line.pop_back();

    // Default Mongoose format: "<time> <level> <file>:<line>:<func> <message>"
    // Level is a single digit: 1=error 2=info 3=debug 4=verbose
    spdlog::level::level_enum lvl = spdlog::level::info;
    std::string msg               = line;

    size_t p1 = line.find(' ');
    if (p1 != std::string::npos && p1 + 1 < line.size()) {
        switch (line[p1 + 1]) {
            case '1':
                lvl = spdlog::level::err;
                break;
            case '2':
                lvl = spdlog::level::info;
                break;
            case '3':
                lvl = spdlog::level::debug;
                break;
            case '4':
                lvl = spdlog::level::trace;
                break;
        }
        // Skip "<time> <level> <file:line:func> " to keep just the message
        size_t p2 = line.find(' ', p1 + 1); // after level
        size_t p3 = (p2 == std::string::npos)
                      ? p2
                      : line.find(' ', p2 + 1); // after file:line:func
        if (p3 != std::string::npos)
            msg = line.substr(p3 + 1);
    }

    spdlog::log(lvl, "[mg] {}", msg);
    line.clear();
}

void
init_mongoose_logging()
{
    mg_log_set_fn(log_to_spdlog, nullptr);
    mg_log_set(
      MG_LL_DEBUG); // Mongoose's own filter, spdlog filters again after
}

// ----------------------------------------------------------------------------

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CControlObject::CControlObject()
{
    // Open syslog

    spdlog::debug("Starting the vscpd daemon");

    m_bQuit = false; // true  for app termination
    m_bQuit_clientMsgWorkerThread =
      false; // true for clientWorkerThread termination

    if (0 != pthread_mutex_init(&m_mutex_DeviceList, NULL)) {
        spdlog::error("Unable to init m_mutex_DeviceList");
        return;
    }

    m_rootFolder = "/var/lib/vscp/vscpd/";

    // Default admin user credentials
    m_vscptoken = "Carpe diem quam minimum credula postero";
    vscp_hexStr2ByteArray(m_systemKey,
                          32,
                          "A4A86F7D7E119BA3F0CD06881E371B989B"
                          "33B6D606A863B633EF529D64544F8E");

    // m_automation.setControlObject(this);
    m_maxItemsInClientReceiveQueue = MAX_ITEMS_CLIENT_RECEIVE_QUEUE;

    // Nill the GUID
    m_guid.clear();

    // Share the control object with the TCP/IP server instance
    m_tcpipSrv.setControlObjectPointer(this);

    // Logging defaults
    m_bEnableFileLog   = false;
    m_fileLogLevel     = spdlog::level::info;
    m_fileLogPattern   = "[mqttvscpd] [%^%l%$] %v";
    m_path_to_log_file = "/var/log/vscp/vscpd.log"; // Directory is created
                                                    // automatically if missing
    m_max_log_size  = 5242880;
    m_max_log_files = 7;

    m_bEnableConsoleLog = true;
    m_consoleLogLevel   = spdlog::level::info;
    m_consoleLogPattern = "[mqttvscpd] [%^%l%$] %v";

    m_bEnableSysLog = false;
    m_sysLogLevel   = spdlog::level::info;
    m_sysLogIdent   = "mqttvscpd";

    m_bEnableUdpLog = false;
    m_udpLogHost    = "127.0.0.1";
    m_udpLogPort    = 9999;
    m_udpLogLevel   = spdlog::level::info;
    m_udpLogPattern = "[%Y-%m-%d %H:%M:%S.%e] [%l] %v";

    // Init. web server subsystem - All features enabled
    // ssl mt locks will we initiated here for openssl 1.0
    // if (0 == mg_init_library(MG_ENABLE_IPV6)) {
    //     spdlog::error( "Failed to initialize webserver subsystem.");
    // }

    // Initialize the CRC
    crcInit();
}

///////////////////////////////////////////////////////////////////////////////
// Destructor
//

CControlObject::~CControlObject()
{

    spdlog::debug("Cleaning up");

    if (0 != pthread_mutex_destroy(&m_mutex_DeviceList)) {
        spdlog::error("Unable to destroy m_mutex_DeviceList");
        return;
    }

    spdlog::debug("Terminating the vscpd daemon");

    // Close syslog
}

/////////////////////////////////////////////////////////////////////////////
// init
//

bool
CControlObject::init(std::string& strcfgfile, std::string& rootFolder)
{
    std::string str;

    // Sodium init
    if (sodium_init() < 0) { // call once at startup
        std::fprintf(stderr, "libsodium init failed\n");
        return false;
    }

    // Save root folder for later use.
    m_rootFolder = rootFolder;

    // Root folder must exist
    if (!vscp_fileExists(m_rootFolder.c_str())) {
        spdlog::error("The specified rootfolder does not exist (%s).",
                      (const char*)m_rootFolder.c_str());
        return false;
    }

    // Change locale to get the correct decimal point "."
    setlocale(LC_NUMERIC, "C");

    // A configuration file must be available
    if (!vscp_fileExists(strcfgfile.c_str())) {
        printf("No configuration file. Can't initialize!.");
        spdlog::error("No configuration file. Can't initialize!. Path=%s",
                      strcfgfile.c_str());
        return false;
    }

    ////////////////////////////////////////////////////////////////////////////
    //                        Read JSON configuration
    ////////////////////////////////////////////////////////////////////////////

    // Read JSON configuration

    spdlog::debug("Reading configuration file");

    // Read JSON configuration
    try {
        if (!readConfiguration(strcfgfile)) {
            spdlog::error(
              "Unable to open/parse configuration file. Can't initialize! "
              "Path =%s",
              strcfgfile.c_str());
            return false;
        }
    }
    catch (...) {
        spdlog::error("Exception when reading configuration file");
        return FALSE;
    }

    // Use spdlog also for mongoose
    init_mongoose_logging();

#ifndef WIN32
    if (m_runAsUser.length()) {
        struct passwd* pw;
        if (NULL == (pw = getpwnam(m_runAsUser.c_str()))) {
            spdlog::error("Unknown user.");
        }
        else if (setgid(pw->pw_gid) != 0) {
            spdlog::error("setgid() failed. [%s]", strerror(errno));
        }
        else if (setuid(pw->pw_uid) != 0) {
            spdlog::error("setuid() failed. [%s]", strerror(errno));
        }
    }
#endif

    spdlog::debug("Using configuration file: %s", strcfgfile.c_str());

    //==========================================================================
    //                           Add driver user
    //==========================================================================

    // Generate username and password for drivers
    char buf[128];
    randPassword pw(4);

    // Level II Driver Username
    memset(buf, 0, sizeof(buf));
    pw.generatePassword(32, buf);
    m_driverUsername = "drv_";
    m_driverUsername += std::string(buf);

    // Level II Driver Password (can't contain ";" character)
    memset(buf, 0, sizeof(buf));
    pw.generatePassword(32, buf);
    m_driverPassword = buf;

    std::string drvhash;
    // vscp_makePasswordHash(drvhash, std::string(buf));

    m_userList.addUser(m_driverUsername,
                       drvhash,                     // salt;hash
                       "System added driver user.", // full name
                       "System added driver user.", // note
                       nullptr,                     // Pointer to filter
                       "driver",                    // user rights
                       "+127.0.0.0/24",             // Only local
                       "*:*",                       // All events
                       0);

    // Get GUID
    if (m_guid.isNULL()) {
        if (!getGuidFromMacAddress(m_guid)) {
            // We failed to create GUID from MAC address use
            // 'localhost' IP instead as the base.
            getGuidFromIPAddress(m_guid);
        }
    }

    // If no server name set construct one
    if (0 == m_strServerName.length()) {
        m_strServerName = "VSCP Server @ ";
        std::string strguid;
        m_guid.toString(strguid);
        m_strServerName += std::string(strguid);
    }

    str = "VSCP Server started - ";
    str += "Version: ";
    str += VSCPD_DISPLAY_VERSION;
    str += " - ";
    str += VSCPD_COPYRIGHT;
    spdlog::info("{}", str.c_str());

    // Start daemon internal client worker thread
    try {
        startClientMsgWorkerThread();
    }
    catch (...) {
        spdlog::error("Exception when starting message worker thread");
        return FALSE;
    }


    // Start TCP/IP server
    try {
        startTcpipWorkerThread();
    }
    catch (...) {
        spdlog::error("Exception when starting tcp/ip server");
        return FALSE;
    }

    // Load drivers
    try {
        startDeviceWorkerThreads();
    }
    catch (...) {
        spdlog::error("Exception when loading drivers");
        return FALSE;
    }

    return true;
}

/////////////////////////////////////////////////////////////////////////////
// run - Program main loop
//
// Most work is done in the threads at the moment
//

bool
CControlObject::run(void)
{
    std::deque<CClientItem*>::iterator nodeClient;

    // We need to create a clientItem for internal use and add it to the
    // client list
    CClientItem* pClientItem = new CClientItem;
    if (NULL == pClientItem) {
        spdlog::error("Unable to allocate Client item, Ending.");
        return false;
    }

    // This is an active client
    pClientItem->setOpen(true);
    pClientItem->setInterfaceType(
      CClientItem::CLIENT_ITEM_INTERFACE_TYPE_CLIENT_INTERNAL);
    pClientItem->setDeviceName("Internal Server Client.|Started at " +
                               vscpdatetime::Now().getISODateTime());

    // Add the client to the Client List (protected (mutex) in addClient)
    if (!m_clientList.addClient(pClientItem, CClientItem::CLIENT_ID_INTERNAL)) {
        // Failed to add client
        spdlog::error("ControlObject: Failed to add internal client.");
        delete pClientItem;
        return false;
    }

    spdlog::debug("Entering main loop");

#ifdef WITH_SYSTEMD
    sd_notify(0, "READY=1");
#endif

    //-------------------------------------------------------------------------
    //                            MAIN - LOOP
    //-------------------------------------------------------------------------

    struct timespec now, old_now;
    timespec_get(&old_now, TIME_UTC);
    old_now.tv_sec -= 60; // Do firts send right away

    while (!m_bQuit) {

        timespec_get(&now, TIME_UTC);

        // We send heartbeat every minute
        if ((now.tv_sec - old_now.tv_sec) > 60) {

            // Save time
            timespec_get(&old_now, TIME_UTC);

            if (!doAutomation(pClientItem)) {
                spdlog::error("Failed to send automation events!");
            }
        }

        // Wait for semaphore indicating events have been sent to all clients
        int rv = m_clientList.waitForOutputQueueEvent(100);
        if (rv == -1) {
            if (errno == ETIMEDOUT) {
                continue;
            }
            spdlog::error("Error waiting for output queue event: {}",
                          strerror(errno));
            break;
        }
        // if ((-1 == vscp_sem_wait(&m_clientList.m_semSentToAllClients, 10)) &&
        //     errno == ETIMEDOUT) {
        //     continue;
        // }

        

        //----------------------------------------------------------------------
        //                         Event received here
        //                   from one of the incoming source
        //----------------------------------------------------------------------

        vscpEvent* pev = pClientItem->getEventFromClientInputQueue(true);
        if (NULL == pev) {
            continue;
        }
        
        // Process the received event here
        // TODO


        vscp_deleteEvent_v2(&pev);

        // mg_mgr_poll(&mgr, 100); // Infinite event loop, blocks for upto 100ms
        //  unless there is network activity

    } // while

    // Remove messages in the client queues (protected inside removeClient)
    m_clientList.removeClient(pClientItem);

    // Clean up is called in main file

    spdlog::debug("Mainloop ending");

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// addClient
//
// Add a client to the control object's client list using an ID.
//

bool
CControlObject::addClient(CClientItem* pClientItem, uint16_t id)
{
    return m_clientList.addClient(pClientItem, id);
}

///////////////////////////////////////////////////////////////////////////////
// addClient
//
// Add a client to the control object's client list using a GUID.
//

bool
CControlObject::addClient(CClientItem* pClientItem, cguid& guid)
{
    return m_clientList.addClient(pClientItem, guid);
}

/////////////////////////////////////////////////////////////////////////////
// automation

bool
CControlObject::doAutomation(CClientItem* pClientItem)
{
    vscpEventEx ex;

    // Send VSCP_CLASS1_INFORMATION,
    // Type=9/VSCP_TYPE_INFORMATION_NODE_HEARTBEAT
    ex.obid      = 0; // IMPORTANT Must be set by caller before event is sent
    ex.head      = 0;
    ex.timestamp = vscp_makeTimeStamp();
    vscp_setEventExToNow(&ex); // Set time to current time
    ex.vscp_class = VSCP_CLASS1_INFORMATION;
    ex.vscp_type  = VSCP_TYPE_INFORMATION_NODE_HEARTBEAT;
    ex.sizeData   = 3;

    // GUID
    memcpy(ex.data + VSCP_CAPABILITY_OFFSET_GUID, m_guid.getGUID(), 16);

    ex.data[0] = 0; // index
    ex.data[1] = 0; // zone
    ex.data[2] = 0; // subzone

    // if (!sendEvent(pClientItem, &ex)) {
    //     spdlog::error("Failed to send Class1 heartbeat");
    // }

    // Send VSCP_CLASS2_INFORMATION,
    // Type=2/VSCP2_TYPE_INFORMATION_HEART_BEAT
    ex.obid      = 0; // IMPORTANT Must be set by caller before event is sent
    ex.head      = 0;
    ex.timestamp = vscp_makeTimeStamp();
    vscp_setEventExToNow(&ex); // Set time to current time
    ex.vscp_class = VSCP_CLASS2_INFORMATION;
    ex.vscp_type  = VSCP2_TYPE_INFORMATION_HEART_BEAT;
    ex.sizeData   = 64;

    // GUID
    memcpy(ex.data + VSCP_CAPABILITY_OFFSET_GUID, m_guid.getGUID(), 16);

    memset(ex.data, 0, sizeof(ex.data));
    memcpy(ex.data,
           m_strServerName.c_str(),
           std::min((int)strlen(m_strServerName.c_str()), 64));

    // if (!sendEvent(pClientItem, &ex)) {
    //     spdlog::error("Failed to send Class2 heartbeat");
    // }

    // Send VSCP_CLASS1_PROTOCOL,
    // Type=1/VSCP_TYPE_PROTOCOL_SEGCTRL_HEARTBEAT
    ex.obid      = 0; // IMPORTANT Must be set by caller before event is sent
    ex.head      = 0;
    ex.timestamp = vscp_makeTimeStamp();
    vscp_setEventExToNow(&ex); // Set time to current time
    ex.vscp_class = VSCP_CLASS1_PROTOCOL;
    ex.vscp_type  = VSCP_TYPE_PROTOCOL_SEGCTRL_HEARTBEAT;
    ex.sizeData   = 5;

    // GUID
    memcpy(ex.data + VSCP_CAPABILITY_OFFSET_GUID, m_guid.getGUID(), 16);

    time_t tnow;
    time(&tnow);
    uint32_t time32 = (uint32_t)tnow;

    ex.data[0] = 0; // 8 - bit crc for VSCP daemon GUID
    ex.data[1] = (uint8_t)((time32 >> 24) & 0xff); // Time since epoch MSB
    ex.data[2] = (uint8_t)((time32 >> 16) & 0xff);
    ex.data[3] = (uint8_t)((time32 >> 8) & 0xff);
    ex.data[4] = (uint8_t)((time32) & 0xff); // Time since epoch LSB

    // if (!sendEvent(pClientItem, &ex)) {
    //     spdlog::error("Failed to send segment controller heartbeat");
    // }

    // Send VSCP_CLASS2_PROTOCOL,
    // Type=20/VSCP2_TYPE_PROTOCOL_HIGH_END_SERVER_CAPS
    ex.obid      = 0; // IMPORTANT Must be set by caller before event is sent
    ex.head      = 0;
    ex.timestamp = vscp_makeTimeStamp();
    vscp_setEventExToNow(&ex); // Set time to current time
    ex.vscp_class = VSCP_CLASS2_PROTOCOL;
    ex.vscp_type  = VSCP2_TYPE_PROTOCOL_HIGH_END_SERVER_CAPS;

    // Fill in data
    memset(ex.data, 0, sizeof(ex.data));

    // GUID
    memcpy(ex.data + VSCP_CAPABILITY_OFFSET_GUID, m_guid.getGUID(), 16);

    // Server ip address
    cguid guid;
    if (getGuidFromIPAddress(guid)) {
        ex.data[VSCP_CAPABILITY_OFFSET_IP_ADDR]     = guid.getAt(8);
        ex.data[VSCP_CAPABILITY_OFFSET_IP_ADDR + 1] = guid.getAt(9);
        ex.data[VSCP_CAPABILITY_OFFSET_IP_ADDR + 2] = guid.getAt(10);
        ex.data[VSCP_CAPABILITY_OFFSET_IP_ADDR + 3] = guid.getAt(11);
    }

    // Server name
    memcpy(ex.data + VSCP_CAPABILITY_OFFSET_SRV_NAME,
           (const char*)m_strServerName.c_str(),
           std::min((int)strlen((const char*)m_strServerName.c_str()), 64));

    // Capabilities array
    getVscpCapabilities(ex.data);

    // non-standard ports
    // TODO

    ex.sizeData = 104;

    // if (!sendEvent(pClientItem, &ex)) {
    //     spdlog::error("Failed to send high end server capabilities.");
    // }

    return true;
}

/////////////////////////////////////////////////////////////////////////////
// cleanup

bool
CControlObject::cleanup(void)
{

    spdlog::debug("ControlObject: cleanup - Giving worker threads time to stop "
                  "operations...");

    spdlog::debug("ControlObject: cleanup - Stopping device worker thread...");

    try {
        stopDeviceWorkerThreads();
    }
    catch (...) {
        spdlog::error(
          "REST: Exception occurred when stoping device worker threads");
    }

    spdlog::debug(
      "ControlObject: cleanup - Stopping VSCP Server worker thread...");

    // stopDaemonWorkerThread(); *****

    spdlog::debug("ControlObject: cleanup - Stopping client worker thread...");

    try {
        stopClientMsgWorkerThread();
    }
    catch (...) {
        spdlog::error("Exception occurred when stoping client worker thread");
    }

    spdlog::debug(
      "ControlObject: cleanup - Stopping Web Server worker thread...");

    try {
        // stop_webserver();
    }
    catch (...) {
        spdlog::error("cleanup: Exception occurred when stoping web server");
    }

    spdlog::debug("ControlObject: cleanup - Stopping TCP/IP worker thread...");

    try {
        stopTcpipWorkerThread();
    }
    catch (...) {
        spdlog::error("cleanup: Exception occurred when stoping tcp/ip server");
    }

    spdlog::debug("Controlobject:  Cleanup done.");

    return true;
}

/////////////////////////////////////////////////////////////////////////////
// startClientMsgWorkerThread
//

bool
CControlObject::startClientMsgWorkerThread(void)
{

    spdlog::debug("Controlobject: Starting client worker thread...");

    if (pthread_create(&m_clientMsgWorkerThread,
                       NULL,
                       clientMsgWorkerThread,
                       this)) {

        spdlog::error("Controlobject: Unable to start client thread.");
        return false;
    }

    return true;
}



/////////////////////////////////////////////////////////////////////////////
// stopClientMsgWorkerThread
//

bool
CControlObject::stopClientMsgWorkerThread(void)
{
    // Request therad to terminate
    setclientWorkerThreadQuit();
    pthread_join(m_clientMsgWorkerThread, NULL);

    return true;
}

/////////////////////////////////////////////////////////////////////////////
// startTcpipWorkerThread
//

bool
CControlObject::startTcpipWorkerThread(void)
{
    spdlog::debug("Controlobject: Starting TCP/IP interface...");

    if (pthread_create(&m_tcpipWorkerThread,
                       NULL,
                       tcpipWorkerThread,
                       &m_tcpipSrv)) {
        spdlog::error(
          "Controlobject: Unable to start the tcp/ip worker thread.");
        return false;
    }

    return true;
}

/////////////////////////////////////////////////////////////////////////////
// stopTcpipWorkerThread
//

bool
CControlObject::stopTcpipWorkerThread(void)
{
    // Tell the thread it's time to quit
    m_tcpipSrv.stopServer();

    spdlog::debug("Controlobject: Terminating TCP/IP worker thread.");

    pthread_join(m_tcpipWorkerThread, NULL);


    spdlog::debug("Controlobject: Terminated TCP thread.");

    return true;
}

////////////////////////////////////////////////////////////////////////////////
// startDeviceWorkerThreads
//

bool
CControlObject::startDeviceWorkerThreads(void)
{
    CDeviceItem* pDeviceItem;

    spdlog::debug("[Controlobject][Driver] - Starting drivers...");

    std::deque<CDeviceItem*>::iterator it;
    for (it = m_deviceList.m_devItemList.begin();
         it != m_deviceList.m_devItemList.end();
         ++it) {

        pDeviceItem = *it;
        if (NULL != pDeviceItem) {

            spdlog::debug("Controlobject: [Driver] - Preparing: %s ",
                          pDeviceItem->getName().c_str());

            // Just start if enabled
            if (!pDeviceItem->isEnabled())
                continue;

            spdlog::debug("Controlobject: [Driver] - Starting: %s ",
                          pDeviceItem->getName().c_str());

            // Start  the driver logic
            pDeviceItem->startDriver(this);

        } // Valid device item
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
// stopDeviceWorkerThreads
//

bool
CControlObject::stopDeviceWorkerThreads(void)
{
    CDeviceItem* pDeviceItem;

    spdlog::debug("[Controlobject][Driver] - Stopping drivers...");

    std::deque<CDeviceItem*>::iterator iter;
    for (iter = m_deviceList.m_devItemList.begin();
         iter != m_deviceList.m_devItemList.end();
         ++iter) {

        pDeviceItem = *iter;
        if (NULL != pDeviceItem) {

            spdlog::debug("Controlobject: [Driver] - Stopping: %s ",
                          pDeviceItem->getName().c_str());

            pDeviceItem->stopDriver();
        }
    }

    return true;
}

/////////////////////////////////////////////////////////////////////////////
// generateSessionId
//

bool
CControlObject::generateSessionId(const char* pKey, char* psid)
{
    char buf[8193];

    // Check pointers
    if (NULL == pKey) {
        return false;
    }
    if (NULL == psid) {
        return false;
    }

    if (strlen(pKey) > 256) {
        return false;
    }

    // Generate a random session ID
    time_t t;
    t = time(NULL);
    sprintf(buf,
            "__%s_%X%X%X%X_be_hungry_stay_foolish_%X%X",
            pKey,
            (unsigned int)rand(),
            (unsigned int)rand(),
            (unsigned int)rand(),
            (unsigned int)t,
            (unsigned int)rand(),
            1337);

    vscp_md5(psid, (const unsigned char*)buf, strlen(buf));

    return true;
}

/////////////////////////////////////////////////////////////////////////////
// getVscpCapabilities
//

bool
CControlObject::getVscpCapabilities(uint8_t* pCapability)
{
    // Check pointer
    if (NULL == pCapability)
        return false;

    uint64_t caps = 0;
    memset(pCapability, 0, 8);

    // VSCP Multicast interface
    // if (m_bEnableMulticast) {
    //     caps |= VSCP_SERVER_CAPABILITY_MULTICAST_CHANNEL;
    // }

    // VSCP TCP/IP interface
    caps |= VSCP_SERVER_CAPABILITY_TCPIP;

    // VSCP UDP interface
    // if (m_udpSrvObj.m_bEnable) {
    //     caps |= VSCP_SERVER_CAPABILITY_UDP;
    // }

    // VSCP Multicast announce interface
    // if (m_bEnableMulticastAnnounce) {
    //     caps |= VSCP_SERVER_CAPABILITY_MULTICAST_ANNOUNCE;
    // }

    // VSCP raw Ethernet interface
    if (1) {
        caps |= VSCP_SERVER_CAPABILITY_RAWETH;
    }

    // IPv6 support
    if (0) {
        caps |= VSCP_SERVER_CAPABILITY_IP6;
    }

    // IPv4 support
    if (0) {
        caps |= VSCP_SERVER_CAPABILITY_IP4;
    }

    // SSL support
    if (1) {
        caps |= VSCP_SERVER_CAPABILITY_SSL;
    }

    // +2 tcp/ip connections support
    caps |= VSCP_SERVER_CAPABILITY_TWO_CONNECTIONS;

    // AES256
    caps |= VSCP_SERVER_CAPABILITY_AES256;

    // AES192
    caps |= VSCP_SERVER_CAPABILITY_AES192;

    // AES128
    caps |= VSCP_SERVER_CAPABILITY_AES128;

    for (int i = 0; i < 8; i++) {
        pCapability[i] = caps & 0xff;
        caps           = caps >> 8;
    }

    return true;
}

//////////////////////////////////////////////////////////////////////////////
// addKnowNode
//

void
CControlObject::addKnownNode(cguid& guid, cguid& ifguid, std::string& name)
{
    ; // TODO
}

///////////////////////////////////////////////////////////////////////////////
//  getGuidFromMacAddress
//

bool
CControlObject::getGuidFromMacAddress(cguid& guid)
{
#ifdef WIN32

    bool rv = false;
    NCB Ncb;
    UCHAR uRetCode;
    LANA_ENUM lenum;
    ASTAT Adapter;
    int i;

    // Clear the GUID
    guid.clear();

    memset(&Ncb, 0, sizeof(Ncb));
    Ncb.ncb_command = NCBENUM;
    Ncb.ncb_buffer  = (UCHAR*)&lenum;
    Ncb.ncb_length  = sizeof(lenum);
    uRetCode        = Netbios(&Ncb);
    // printf( "The NCBENUM return code is: 0x%x ", uRetCode );

    for (i = 0; i < lenum.length; i++) {
        memset(&Ncb, 0, sizeof(Ncb));
        Ncb.ncb_command  = NCBRESET;
        Ncb.ncb_lana_num = lenum.lana[i];

        uRetCode = Netbios(&Ncb);

        memset(&Ncb, 0, sizeof(Ncb));
        Ncb.ncb_command  = NCBASTAT;
        Ncb.ncb_lana_num = lenum.lana[i];

        strcpy((char*)Ncb.ncb_callname, "*               ");
        Ncb.ncb_buffer = (unsigned char*)&Adapter;
        Ncb.ncb_length = sizeof(Adapter);

        uRetCode = Netbios(&Ncb);

        if (uRetCode == 0) {
            guid.setAt(0, 0xff);
            guid.setAt(1, 0xff);
            guid.setAt(2, 0xff);
            guid.setAt(3, 0xff);
            guid.setAt(4, 0xff);
            guid.setAt(5, 0xff);
            guid.setAt(6, 0xff);
            guid.setAt(7, 0xfe);
            guid.setAt(8, Adapter.adapt.adapter_address[0]);
            guid.setAt(9, Adapter.adapt.adapter_address[1]);
            guid.setAt(10, Adapter.adapt.adapter_address[2]);
            guid.setAt(11, Adapter.adapt.adapter_address[3]);
            guid.setAt(12, Adapter.adapt.adapter_address[4]);
            guid.setAt(13, Adapter.adapt.adapter_address[5]);
            guid.setAt(14, 0);
            guid.setAt(15, 0);
#ifdef DEBUG__
            char buf[256];
            sprintf(buf,
                    "The Ethernet MAC Address: %02x:%02x:%02x:%02x:%02x:%02x",
                    guid.getAt(2),
                    guid.getAt(3),
                    guid.getAt(4),
                    guid.getAt(5),
                    guid.getAt(6),
                    guid.getAt(7));

            std::string str = std::string(buf);
#endif

            rv = true;
        }
    }

    return rv;

#else
    // cat /sys/class/net/eth0/address
    bool rv = true;
#ifdef __linux__
    struct ifreq s;
    int fd;

    // Clear the GUID
    guid.clear();

    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (-1 == fd)
        return false;

    memset(&s, 0, sizeof(s));
    strcpy(s.ifr_name, "eth0");

    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {

        // ptr = (unsigned char *)&s.ifr_ifru.ifru_hwaddr.sa_data[0];

        spdlog::debug("Ethernet MAC address: %02X:%02X:%02X:%02X:%02X:%02X",
                      (uint8_t)s.ifr_addr.sa_data[0],
                      (uint8_t)s.ifr_addr.sa_data[1],
                      (uint8_t)s.ifr_addr.sa_data[2],
                      (uint8_t)s.ifr_addr.sa_data[3],
                      (uint8_t)s.ifr_addr.sa_data[4],
                      (uint8_t)s.ifr_addr.sa_data[5]);

        guid.setAt(0, 0xff);
        guid.setAt(1, 0xff);
        guid.setAt(2, 0xff);
        guid.setAt(3, 0xff);
        guid.setAt(4, 0xff);
        guid.setAt(5, 0xff);
        guid.setAt(6, 0xff);
        guid.setAt(7, 0xfe);
        guid.setAt(8, s.ifr_addr.sa_data[0]);
        guid.setAt(9, s.ifr_addr.sa_data[1]);
        guid.setAt(10, s.ifr_addr.sa_data[2]);
        guid.setAt(11, s.ifr_addr.sa_data[3]);
        guid.setAt(12, s.ifr_addr.sa_data[4]);
        guid.setAt(13, s.ifr_addr.sa_data[5]);
        guid.setAt(14, 0);
        guid.setAt(15, 0);
    }
    else {
        spdlog::error("Failed to get hardware address (must be root?).");
        rv = false;
    }

    return rv;

#else
    // SIOCGIFHWADDR not available on this platform (e.g. macOS)
    rv = false;
    return rv;
#endif // __linux__

#endif // WIN32
}

///////////////////////////////////////////////////////////////////////////////
//  getGuidFromIPAddress
//

bool
CControlObject::getGuidFromIPAddress(cguid& guid)
{
    // Clear the GUID
    guid.clear();

    guid.setAt(0, 0xff);
    guid.setAt(1, 0xff);
    guid.setAt(2, 0xff);
    guid.setAt(3, 0xff);
    guid.setAt(4, 0xff);
    guid.setAt(5, 0xff);
    guid.setAt(6, 0xff);
    guid.setAt(7, 0xfd);

    char szName[128];
    gethostname(szName, sizeof(szName));
#if defined(_WIN32)
    LPHOSTENT lpLocalHostEntry;
#else
    struct hostent* lpLocalHostEntry;
#endif
    lpLocalHostEntry = gethostbyname(szName);
    if (NULL == lpLocalHostEntry) {
        return false;
    }

    // Get all local addresses
    int idx = -1;
    void* pAddr;
    unsigned long localaddr[16]; // max 16 local addresses
    do {
        idx++;
        localaddr[idx] = 0;
        pAddr          = lpLocalHostEntry->h_addr_list[idx];
        if (NULL != pAddr)
            localaddr[idx] = *((unsigned long*)pAddr);
    } while ((NULL != pAddr) && (idx < 16));

    guid.setAt(8, (localaddr[0] >> 24) & 0xff);
    guid.setAt(9, (localaddr[0] >> 16) & 0xff);
    guid.setAt(10, (localaddr[0] >> 8) & 0xff);
    guid.setAt(11, localaddr[0] & 0xff);

    guid.setAt(12, 0);
    guid.setAt(13, 0);
    guid.setAt(14, 0);
    guid.setAt(15, 0);

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// getSystemKey
//

uint8_t*
CControlObject::getSystemKey(uint8_t* pKey)
{
    if (NULL != pKey) {
        memcpy(pKey, m_systemKey, 32);
    }

    return m_systemKey;
}

///////////////////////////////////////////////////////////////////////////////
// getSystemKeyMD5
//

void
CControlObject::getSystemKeyMD5(std::string& strKey)
{
    char digest[33];
    vscp_md5(digest, m_systemKey, 32);
    strKey = digest;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// readConfiguration
//
// Read the configuration JSON file
//

bool
CControlObject::readConfiguration(const std::string& strcfgfile)
{

    spdlog::debug("Reading full JSON configuration from {}",
                  strcfgfile.c_str());

    json j;
    try {
        std::ifstream in(strcfgfile, std::ifstream::in);
        if (!in.is_open()) {
            spdlog::error("Failed to open configuration file {}",
                          strcfgfile.c_str());
            return false;
        }
        in >> j;
    }
    catch (const std::exception& ex) {
        spdlog::error("Failed to parse JSON configuration file {}: {}",
                      strcfgfile.c_str(),
                      ex.what());
        return false;
    }
    catch (...) {
        spdlog::error("Failed to parse JSON configuration file {}",
                      strcfgfile.c_str());
        return false;
    }

    auto get_string = [](const json& node, const char* key, std::string& out) {
        if (node.contains(key) && node[key].is_string()) {
            out = node[key].get<std::string>();
            spdlog::debug("ReadConfig: Read string setting '{}'.", key);
            return true;
        }
        spdlog::debug("ReadConfig: String setting '{}' missing or invalid; "
                      "default retained.",
                      key);
        return false;
    };

    auto get_bool = [](const json& node, const char* key, bool& out) {
        if (!node.contains(key)) {
            return false;
        }
        if (node[key].is_boolean()) {
            out = node[key].get<bool>();
            return true;
        }
        if (node[key].is_string()) {
            std::string v = node[key].get<std::string>();
            vscp_makeLower(v);
            out = ("true" == v) || ("1" == v) || ("yes" == v);
            return true;
        }
        if (node[key].is_number_integer()) {
            out = (0 != node[key].get<int>());
            return true;
        }
        return false;
    };

    auto get_uint = [](const json& node, const char* key, uint32_t& out) {
        if (node.contains(key) && node[key].is_number_integer()) {
            out = node[key].get<uint32_t>();
            spdlog::debug("ReadConfig: Read integer setting '{}'.", key);
            return true;
        }
        spdlog::debug("ReadConfig: Integer setting '{}' missing or invalid; "
                      "default retained.",
                      key);
        return false;
    };

    // Logging
    if (!(j.contains("logging") && j["logging"].is_object())) {
        spdlog::debug(
          "ReadConfig: logging object. Defaults will be used for all values.");
    }
    else {

        // Logging: file-enable-log
        if (j["logging"].contains("file-enable-log")) {
            try {
                m_bEnableFileLog = j["logging"]["file-enable-log"].get<bool>();
            }
            catch (const std::exception& ex) {
                spdlog::error(
                  "ReadConfig: Failed to read 'file-enable-log' Error='{}'",
                  ex.what());
            }
            catch (...) {
                spdlog::error("ReadConfig: Failed to read 'file-enable-log' "
                              "due to unknown error.");
            }
            spdlog::debug("ReadConfig: LOGGING 'file-enable-log' set to {}",
                          m_bEnableFileLog ? "true" : "false");
        }
        else {
            spdlog::debug("ReadConfig: Failed to read LOGGING "
                          "'file-enable-log' Defaults will be used.");
        }

        // Logging: file-log-level
        if (j["logging"].contains("file-log-level")) {
            std::string str;
            try {
                str = j["logging"]["file-log-level"].get<std::string>();
            }
            catch (const std::exception& ex) {
                spdlog::error(
                  "ReadConfig: Failed to read 'file-log-level' Error='{}'",
                  ex.what());
            }
            catch (...) {
                spdlog::error("ReadConfig: Failed to read 'file-log-level' due "
                              "to unknown error.");
            }
            vscp_makeLower(str);
            if (std::string::npos != str.find("off")) {
                m_fileLogLevel = spdlog::level::off;
                spdlog::debug(
                  "ReadConfig: LOGGING 'file-log-level' set to 'off'.");
            }
            else if (std::string::npos != str.find("critical")) {
                m_fileLogLevel = spdlog::level::critical;
                spdlog::debug(
                  "ReadConfig: LOGGING 'file-log-level' set to 'critical'.");
            }
            else if (std::string::npos != str.find("err")) {
                m_fileLogLevel = spdlog::level::err;
                spdlog::debug(
                  "ReadConfig: LOGGING 'file-log-level' set to 'err'.");
            }
            else if (std::string::npos != str.find("warn")) {
                m_fileLogLevel = spdlog::level::warn;
                spdlog::debug(
                  "ReadConfig: LOGGING 'file-log-level' set to 'warn'.");
            }
            else if (std::string::npos != str.find("info")) {
                m_fileLogLevel = spdlog::level::info;
                spdlog::debug(
                  "ReadConfig: LOGGING 'file-log-level' set to 'info'.");
            }
            else if (std::string::npos != str.find("debug")) {
                m_fileLogLevel = spdlog::level::debug;
                spdlog::debug(
                  "ReadConfig: LOGGING 'file-log-level' set to 'debug'.");
            }
            else if (std::string::npos != str.find("trace")) {
                m_fileLogLevel = spdlog::level::trace;
                spdlog::debug(
                  "ReadConfig: LOGGING 'file-log-level' set to 'trace'.");
            }
            else {
                spdlog::debug("ReadConfig: LOGGING 'file-log-level' has "
                              "invalid value [{}]. Default value used.",
                              str);
            }
        }
        else {
            spdlog::debug("ReadConfig: Failed to read LOGGING 'file-log-level' "
                          "Defaults will be used.");
        }

        // Logging: file-pattern
        if (j["logging"].contains("file-pattern")) {
            try {
                m_fileLogPattern =
                  j["logging"]["file-pattern"].get<std::string>();
            }
            catch (const std::exception& ex) {
                spdlog::error(
                  "ReadConfig: Failed to read 'file-pattern' Error='{}'",
                  ex.what());
            }
            catch (...) {
                spdlog::error("ReadConfig: Failed to read 'file-pattern' due "
                              "to unknown error.");
            }
            spdlog::debug("ReadConfig: LOGGING 'file-pattern' set to {}.",
                          m_fileLogPattern);
        }
        else {
            spdlog::debug("ReadConfig: Failed to read LOGGING 'file-pattern' "
                          "Defaults will be used.");
        }

        // Logging: file-path
        if (j["logging"].contains("file-path")) {
            try {
                m_path_to_log_file =
                  j["logging"]["file-path"].get<std::string>();
            }
            catch (const std::exception& ex) {
                spdlog::error(
                  "ReadConfig: Failed to read 'file-path' Error='{}'",
                  ex.what());
            }
            catch (...) {
                spdlog::error("ReadConfig: Failed to read 'file-path' due to "
                              "unknown error.");
            }
            spdlog::debug("ReadConfig: LOGGING 'file-path' set to '{}'.",
                          m_path_to_log_file);
        }
        else {
            spdlog::debug("ReadConfig: Failed to read LOGGING 'file-path' "
                          "Defaults will be used.");
        }

        // Logging: file-max-size
        if (j["logging"].contains("file-max-size")) {
            try {
                m_max_log_size = j["logging"]["file-max-size"].get<uint32_t>();
            }
            catch (const std::exception& ex) {
                spdlog::error(
                  "ReadConfig: Failed to read 'file-max-size' Error='{}'",
                  ex.what());
            }
            catch (...) {
                spdlog::error("ReadConfig: Failed to read 'file-max-size' due "
                              "to unknown error.");
            }
            spdlog::debug("ReadConfig: LOGGING 'file-max-size' set to '{}'.",
                          m_max_log_size);
        }
        else {
            spdlog::debug("ReadConfig: Failed to read LOGGING 'file-max-size' "
                          "Defaults will be used.");
        }

        // Logging: file-max-files
        if (j["logging"].contains("file-max-files")) {
            try {
                m_max_log_files =
                  j["logging"]["file-max-files"].get<uint16_t>();
            }
            catch (const std::exception& ex) {
                spdlog::error(
                  "ReadConfig: Failed to read 'file-max-files' Error='{}'",
                  ex.what());
            }
            catch (...) {
                spdlog::error("ReadConfig: Failed to read 'file-max-files' due "
                              "to unknown error.");
            }
            spdlog::debug("ReadConfig: LOGGING 'file-max-files' set to '{}'.",
                          m_max_log_files);
        }
        else {
            spdlog::debug("ReadConfig: Failed to read LOGGING 'file-max-files' "
                          "Defaults will be used.");
        }

        // Console

        // Logging: console-enable-log
        if (j["logging"].contains("console-enable-log")) {
            try {
                m_bEnableConsoleLog =
                  j["logging"]["console-enable-log"].get<bool>();
            }
            catch (const std::exception& ex) {
                spdlog::error(
                  "ReadConfig: Failed to read 'console-enable-log' Error='{}'",
                  ex.what());
            }
            catch (...) {
                spdlog::error("ReadConfig: Failed to read 'console-enable-log' "
                              "due to unknown error.");
            }
            spdlog::debug("ReadConfig: LOGGING 'console-enable-log' set to {}",
                          m_bEnableConsoleLog ? "true" : "false");
        }
        else {
            spdlog::debug("ReadConfig: Failed to read LOGGING "
                          "'console-enable-log' Defaults will be used.");
        }

        // Logging: console-log-level
        if (j["logging"].contains("console-log-level")) {
            std::string str;
            try {
                str = j["logging"]["console-log-level"].get<std::string>();
            }
            catch (const std::exception& ex) {
                spdlog::error("ReadConfig: Failed to read "
                              "'console-enable-level' Error='{}'",
                              ex.what());
            }
            catch (...) {
                spdlog::error("ReadConfig: Failed to read "
                              "'console-enable-level' due to unknown error.");
            }
            vscp_makeLower(str);
            if (std::string::npos != str.find("off")) {
                m_consoleLogLevel = spdlog::level::off;
                spdlog::debug(
                  "ReadConfig: LOGGING 'console-log-level' set to 'off'.");
            }
            else if (std::string::npos != str.find("critical")) {
                m_consoleLogLevel = spdlog::level::critical;
                spdlog::debug(
                  "ReadConfig: LOGGING 'console-log-level' set to 'critical'.");
            }
            else if (std::string::npos != str.find("err")) {
                m_consoleLogLevel = spdlog::level::err;
                spdlog::debug(
                  "ReadConfig: LOGGING 'console-log-level' set to 'err'.");
            }
            else if (std::string::npos != str.find("warn")) {
                m_consoleLogLevel = spdlog::level::warn;
                spdlog::debug(
                  "ReadConfig: LOGGING 'console-log-level' set to 'warn'.");
            }
            else if (std::string::npos != str.find("info")) {
                m_consoleLogLevel = spdlog::level::info;
                spdlog::debug(
                  "ReadConfig: LOGGING 'console-log-level' set to 'info'.");
            }
            else if (std::string::npos != str.find("debug")) {
                m_consoleLogLevel = spdlog::level::debug;
                spdlog::debug(
                  "ReadConfig: LOGGING 'console-log-level' set to 'debug'.");
            }
            else if (std::string::npos != str.find("trace")) {
                m_consoleLogLevel = spdlog::level::trace;
                spdlog::debug(
                  "ReadConfig: LOGGING 'console-log-level' set to 'trace'.");
            }
            else {
                spdlog::debug("ReadConfig: LOGGING 'console-log-level' has "
                              "invalid value [{}]. Default value used.",
                              str);
            }
        }
        else {
            spdlog::debug("ReadConfig: Failed to read LOGGING 'file-log-level' "
                          "Defaults will be used.");
        }

        // Logging: console-pattern
        if (j["logging"].contains("console-pattern")) {
            try {
                m_consoleLogPattern =
                  j["logging"]["console-pattern"].get<std::string>();
            }
            catch (const std::exception& ex) {
                spdlog::error(
                  "ReadConfig: Failed to read 'console-pattern' Error='{}'",
                  ex.what());
            }
            catch (...) {
                spdlog::error("ReadConfig: Failed to read 'console-pattern' "
                              "due to unknown error.");
            }
            spdlog::debug("ReadConfig: LOGGING 'console-pattern' set to {}.",
                          m_consoleLogPattern);
        }
        else {
            spdlog::debug("ReadConfig: Failed to read LOGGING "
                          "'console-pattern' Defaults will be used.");
        }

        // syslog

        // Logging: syslog-enable-log
        if (j["logging"].contains("syslog-enable-log")) {
            try {
                m_bEnableSysLog = j["logging"]["syslog-enable-log"].get<bool>();
            }
            catch (const std::exception& ex) {
                spdlog::error(
                  "ReadConfig: Failed to read 'syslog-enable-log' Error='{}'",
                  ex.what());
            }
            catch (...) {
                spdlog::error("ReadConfig: Failed to read 'syslog-enable-log' "
                              "due to unknown error.");
            }
            spdlog::debug("ReadConfig: LOGGING 'syslog-enable-log' set to {}",
                          m_bEnableSysLog ? "true" : "false");
        }
        else {
            spdlog::debug("ReadConfig: Failed to read LOGGING "
                          "'syslog-enable-log' Defaults will be used.");
        }

        // Logging: syslog-log-level
        if (j["logging"].contains("syslog-log-level")) {
            std::string str;
            try {
                str = j["logging"]["syslog-log-level"].get<std::string>();
            }
            catch (const std::exception& ex) {
                spdlog::error(
                  "ReadConfig: Failed to read 'syslog-log-level' Error='{}'",
                  ex.what());
            }
            catch (...) {
                spdlog::error("ReadConfig: Failed to read 'syslog-log-level' "
                              "due to unknown error.");
            }
            vscp_makeLower(str);
            if (std::string::npos != str.find("off")) {
                m_sysLogLevel = spdlog::level::off;
                spdlog::debug(
                  "ReadConfig: LOGGING 'syslog-log-level' set to 'off'.");
            }
            else if (std::string::npos != str.find("critical")) {
                m_sysLogLevel = spdlog::level::critical;
                spdlog::debug(
                  "ReadConfig: LOGGING 'syslog-log-level' set to 'critical'.");
            }
            else if (std::string::npos != str.find("err")) {
                m_sysLogLevel = spdlog::level::err;
                spdlog::debug(
                  "ReadConfig: LOGGING 'syslog-log-level' set to 'err'.");
            }
            else if (std::string::npos != str.find("warn")) {
                m_sysLogLevel = spdlog::level::warn;
                spdlog::debug(
                  "ReadConfig: LOGGING 'syslog-log-level' set to 'warn'.");
            }
            else if (std::string::npos != str.find("info")) {
                m_sysLogLevel = spdlog::level::info;
                spdlog::debug(
                  "ReadConfig: LOGGING 'syslog-log-level' set to 'info'.");
            }
            else if (std::string::npos != str.find("debug")) {
                m_sysLogLevel = spdlog::level::debug;
                spdlog::debug(
                  "ReadConfig: LOGGING 'syslog-log-level' set to 'debug'.");
            }
            else if (std::string::npos != str.find("trace")) {
                m_sysLogLevel = spdlog::level::trace;
                spdlog::debug(
                  "ReadConfig: LOGGING 'syslog-log-level' set to 'trace'.");
            }
            else {
                spdlog::debug("ReadConfig: LOGGING 'syslog-log-level' has "
                              "invalid value [{}]. Default value used.",
                              str);
            }
        }
        else {
            spdlog::debug("ReadConfig: Failed to read LOGGING "
                          "'syslog-log-level' Defaults will be used.");
        }

        // Logging: syslog-ident
        if (j["logging"].contains("syslog-ident")) {
            try {
                m_sysLogIdent = j["logging"]["syslog-ident"].get<std::string>();
            }
            catch (const std::exception& ex) {
                spdlog::error(
                  "ReadConfig: Failed to read 'syslog-ident' Error='{}'",
                  ex.what());
            }
            catch (...) {
                spdlog::error("ReadConfig: Failed to read 'syslog-ident' due "
                              "to unknown error.");
            }
            spdlog::debug("ReadConfig: LOGGING 'syslog-ident' set to {}.",
                          m_sysLogIdent);
        }
        else {
            spdlog::debug("ReadConfig: Failed to read LOGGING 'syslog-ident' "
                          "Defaults will be used.");
        }

        // UDP logging
        if (j["logging"].contains("udp-enable-log")) {
            try {
                m_bEnableUdpLog = j["logging"]["udp-enable-log"].get<bool>();
            }
            catch (const std::exception& ex) {
                spdlog::error(
                  "ReadConfig: Failed to read 'udp-enable-log' Error='{}'",
                  ex.what());
            }
            catch (...) {
                spdlog::error("ReadConfig: Failed to read 'udp-enable-log' due "
                              "to unknown error.");
            }
            spdlog::debug("ReadConfig: LOGGING 'udp-enable-log' set to {}",
                          m_bEnableUdpLog ? "true" : "false");
        }
        else {
            spdlog::debug("ReadConfig: Failed to read LOGGING 'udp-enable-log' "
                          "Defaults will be used.");
        }

        // UDP logging level
        if (j["logging"].contains("udp-log-level")) {
            std::string str;
            try {
                str = j["logging"]["udp-log-level"].get<std::string>();
            }
            catch (const std::exception& ex) {
                spdlog::error(
                  "ReadConfig: Failed to read 'udp-log-level' Error='{}'",
                  ex.what());
            }
            catch (...) {
                spdlog::error("ReadConfig: Failed to read 'udp-log-level' due "
                              "to unknown error.");
            }
            vscp_makeLower(str);
            if (std::string::npos != str.find("off")) {
                m_udpLogLevel = spdlog::level::off;
                spdlog::debug(
                  "ReadConfig: LOGGING 'udp-log-level' set to 'off'.");
            }
            else if (std::string::npos != str.find("critical")) {
                m_udpLogLevel = spdlog::level::critical;
                spdlog::debug(
                  "ReadConfig: LOGGING 'udp-log-level' set to 'critical'.");
            }
            else if (std::string::npos != str.find("err")) {
                m_udpLogLevel = spdlog::level::err;
                spdlog::debug(
                  "ReadConfig: LOGGING 'udp-log-level' set to 'err'.");
            }
            else if (std::string::npos != str.find("warn")) {
                m_udpLogLevel = spdlog::level::warn;
                spdlog::debug(
                  "ReadConfig: LOGGING 'udp-log-level' set to 'warn'.");
            }
            else if (std::string::npos != str.find("info")) {
                m_udpLogLevel = spdlog::level::info;
                spdlog::debug(
                  "ReadConfig: LOGGING 'udp-log-level' set to 'info'.");
            }
            else if (std::string::npos != str.find("debug")) {
                m_udpLogLevel = spdlog::level::debug;
                spdlog::debug(
                  "ReadConfig: LOGGING 'udp-log-level' set to 'debug'.");
            }
            else if (std::string::npos != str.find("trace")) {
                m_udpLogLevel = spdlog::level::trace;
                spdlog::debug(
                  "ReadConfig: LOGGING 'udp-log-level' set to 'trace'.");
            }
            else {
                spdlog::debug("ReadConfig: LOGGING 'udp-log-level' has invalid "
                              "value [{}]. Default value used.",
                              str);
            }
        } // UDP logging level

        // Logging: udp-pattern
        if (j["logging"].contains("udp-pattern")) {
            try {
                m_udpLogPattern =
                  j["logging"]["udp-pattern"].get<std::string>();
            }
            catch (const std::exception& ex) {
                spdlog::error(
                  "ReadConfig: Failed to read 'udp-pattern' Error='{}'",
                  ex.what());
            }
            catch (...) {
                spdlog::error("ReadConfig: Failed to read 'udp-pattern' due to "
                              "unknown error.");
            }
            spdlog::debug("ReadConfig: LOGGING 'udp-pattern' set to {}.",
                          m_udpLogPattern);
        }
        else {
            spdlog::debug("ReadConfig: Failed to read LOGGING 'udp-pattern'. "
                          "Defaults will be used.");
        }

        // Logging: udp-host
        if (j["logging"].contains("udp-host")) {
            try {
                m_udpLogHost = j["logging"]["udp-host"].get<std::string>();
            }
            catch (const std::exception& ex) {
                spdlog::error(
                  "ReadConfig: Failed to read 'udp-host' Error='{}'",
                  ex.what());
            }
            catch (...) {
                spdlog::error("ReadConfig: Failed to read 'udp-host' due to "
                              "unknown error.");
            }
            spdlog::debug("ReadConfig: LOGGING 'udp-host' set to {}.",
                          m_udpLogHost);
        }
        else {
            spdlog::debug("ReadConfig: Failed to read LOGGING 'udp-host' "
                          "Defaults will be used.");
        }

        // Logging: udp-port
        if (j["logging"].contains("udp-port")) {
            try {
                m_udpLogPort = j["logging"]["udp-port"].get<uint16_t>();
            }
            catch (const std::exception& ex) {
                spdlog::error(
                  "ReadConfig: Failed to read 'udp-port' Error='{}'",
                  ex.what());
            }
            catch (...) {
                spdlog::error(
                  "Failed to read 'udp-port' due to unknown error.");
            }
            spdlog::debug("ReadConfig: LOGGING 'udp-port' set to {}.",
                          m_udpLogPort);
        }
        else {
            spdlog::debug("ReadConfig: Failed to read LOGGING 'udp-port' "
                          "Defaults will be used.");
        }

    } // logging

    // Top-level/general fields.
    get_string(j, "runasuser", m_runAsUser);
    get_string(j, "servername", m_strServerName);

    // GUID is set from mac address or IP address if not explicitly specified.
    // This is done in the constructor
    if (j.contains("guid") && j["guid"].is_string()) {
        m_guid.getFromString(j["guid"].get<std::string>());
        spdlog::debug("ReadConfig: Read top-level 'guid'.");
    }
    else {
        spdlog::debug(
          "ReadConfig: 'guid' not found or invalid, using default GUID.");
    }

    // Optional legacy/general object support.
    if (j.contains("general") && j["general"].is_object()) {
        const json& g = j["general"];
        get_string(g, "runasuser", m_runAsUser);
        get_string(g, "servername", m_strServerName);
        if (g.contains("guid") && g["guid"].is_string()) {
            m_guid.getFromString(g["guid"].get<std::string>());
            spdlog::debug("ReadConfig: Read general 'guid'.");
        }
        if (g.contains("clientbuffersize") &&
            g["clientbuffersize"].is_number_integer()) {
            m_maxItemsInClientReceiveQueue =
              g["clientbuffersize"].get<uint32_t>();
            spdlog::debug("ReadConfig: Read general 'clientbuffersize' as {}.",
                          m_maxItemsInClientReceiveQueue);
        }
        else {
            spdlog::debug("ReadConfig: General 'clientbuffersize' missing or "
                          "invalid; default retained.");
        }
    }
    else {
        spdlog::debug("ReadConfig: 'general' object missing or invalid; "
                      "defaults retained.");
    }

    // Security.
    if (j.contains("security") && j["security"].is_object()) {
        const json& sec = j["security"];
        get_string(sec, "admin", m_admin_user);
        get_string(sec, "password", m_admin_password);
        get_string(sec, "allowfrom", m_admin_allowfrom);
        get_string(sec, "vscptoken", m_vscptoken);
        // get_string(sec, "authentication_domain",
        // m_web_authentication_domain);
        if (sec.contains("vscpkey") && sec["vscpkey"].is_string()) {
            vscp_hexStr2ByteArray(m_systemKey,
                                  32,
                                  sec["vscpkey"].get<std::string>().c_str());
            spdlog::debug("ReadConfig: Read security 'vscpkey'.");
        }
        else {
            spdlog::debug("ReadConfig: Security 'vscpkey' missing or invalid; "
                          "default retained.");
        }
    }
    else {
        spdlog::debug("ReadConfig: 'security' object missing or invalid; "
                      "defaults retained.");
    }

    // TCP/IP section.
    if (j.contains("tcpip") && j["tcpip"].is_object()) {
        const json& jj = j["tcpip"];
        bool b         = false;
        uint32_t n     = 0;
        
        std::string addr;
        get_string(jj, "interface-address", addr);
        m_tcpipSrv.setInterfaceAddress(addr);

        if (jj.contains("ssl-options") && jj["ssl-options"].is_object()) {
            const json& jjj = jj["ssl-options"];
            std::string str;
            get_string(jjj, "cafile", str);
            m_tcpipSrv.getTlsOpts().ca = mg_str(str.c_str());
            get_string(jjj, "certfile", str);
            m_tcpipSrv.getTlsOpts().cert = mg_str(str.c_str());
            get_string(jjj, "keyfile", str);
            m_tcpipSrv.getTlsOpts().key = mg_str(str.c_str());
            get_string(jjj, "name", str);
            m_tcpipSrv.getTlsOpts().name = mg_str(str.c_str());
        }
        else {
            spdlog::debug("ReadConfig: TCP/IP 'ssl-options' object missing or "
                          "invalid; defaults retained.");
        }
    }
    else {
        spdlog::debug(
          "ReadConfig: 'tcpip' object missing or invalid; defaults retained.");
    }

    // Users.
    if (j.contains("remoteuser") && j["remoteuser"].is_array()) {
        spdlog::debug("ReadConfig: Read 'remoteuser' array with {} entries.",
                      j["remoteuser"].size());

        for (const auto& u : j["remoteuser"]) {
            if (!u.is_object()) {
                spdlog::debug(
                  "ReadConfig: Skipping non-object entry in 'remoteuser'.");
                continue;
            }

            std::string username;
            std::string password;
            std::string fullname;
            std::string note;
            std::string privilege;
            std::string allowfrom;
            std::string allowevents;
            std::string filter;
            std::string mask;
            uint32_t flags = 0;

            get_string(u, "username", username);
            get_string(u, "password", password);
            get_string(u, "fullname", fullname);
            get_string(u, "note", note);
            get_string(u, "privilege", privilege);
            get_string(u, "allowed_remotes", allowfrom);
            get_string(u, "allowed_events", allowevents);
            get_string(u, "filter", filter);
            get_string(u, "mask", mask);
            get_uint(u, "flags", flags);

            // Skip users without a name or password.
            if (username.empty() || password.empty()) {
                continue;
            }

            vscpEventFilter vfilter;
            vscp_clearVSCPFilter(&vfilter);
            bool hasFilter = false;

            if (!filter.empty() && !mask.empty()) {
                hasFilter = vscp_readFilterFromString(&vfilter, filter) &&
                            vscp_readMaskFromString(&vfilter, mask);
            }

            m_userList.addUser(username,
                               password,
                               fullname,
                               note,
                               hasFilter ? &vfilter : NULL,
                               privilege,
                               allowfrom,
                               allowevents,
                               flags);
        }
    }
    else {
        spdlog::debug("ReadConfig: 'remoteuser' array missing or invalid; no "
                      "users loaded.");
    }

    // Drivers.
    if (j.contains("drivers") && j["drivers"].is_object()) {
        const json& drivers = j["drivers"];

        if (drivers.contains("level1") && drivers["level1"].is_array()) {
            for (const auto& drv : drivers["level1"]) {
                if (!drv.is_object()) {
                    continue;
                }
                const bool enabled = drv.value("enable", false);
                spdlog::debug("ReadConfig: Read level I driver 'enable' as {}.",
                              enabled ? "true" : "false");
                if (!enabled || !drv.contains("name") ||
                    !drv.contains("config") || !drv.contains("path") ||
                    !drv.contains("flags") || !drv.contains("guid") ||
                    !drv.contains("translation")) {
                    continue;
                }

                std::string strName = drv["name"].get<std::string>();
                std::replace(strName.begin(), strName.end(), ' ', '_');

                cguid guid;
                guid.getFromString(drv["guid"].get<std::string>());
                spdlog::debug("ReadConfig: Read level I driver '{}' settings: "
                              "name, config, path, flags, guid, translation.",
                              strName);

                if (!m_deviceList.addItem(strName,
                                          drv["config"].get<std::string>(),
                                          drv["path"].get<std::string>(),
                                          drv["flags"].get<uint32_t>(),
                                          guid,
                                          VSCP_DRIVER_LEVEL1,
                                          true,
                                          drv["translation"].get<uint32_t>())) {
                    spdlog::error(
                      "Level I driver not added name=%s. Path does not "
                      "exist. - [%s]",
                      strName.c_str(),
                      drv["path"].get<std::string>().c_str());
                }
            }
        }
        else {
            spdlog::debug(
              "ReadConfig: 'drivers.level1' array missing or invalid.");
        }

        if (drivers.contains("level2") && drivers["level2"].is_array()) {
            for (const auto& drv : drivers["level2"]) {
                if (!drv.is_object()) {
                    continue;
                }
                const bool enabled = drv.value("enable", false);
                spdlog::debug(
                  "ReadConfig: Read level II driver 'enable' as {}.",
                  enabled ? "true" : "false");
                if (!enabled || !drv.contains("name") ||
                    !drv.contains("path-config") ||
                    !drv.contains("path-driver") || !drv.contains("guid")) {
                    continue;
                }

                std::string strName = drv["name"].get<std::string>();
                std::replace(strName.begin(), strName.end(), ' ', '_');

                cguid guid;
                guid.getFromString(drv["guid"].get<std::string>());
                spdlog::debug("ReadConfig: Read level II driver '{}' settings: "
                              "name, path-config, path-driver, guid.",
                              strName);

                if (!m_deviceList.addItem(strName,
                                          drv["path-config"].get<std::string>(),
                                          drv["path-driver"].get<std::string>(),
                                          0,
                                          guid,
                                          VSCP_DRIVER_LEVEL2,
                                          true)) {
                    spdlog::error(
                      "Level II driver not added name=%s. Path does not "
                      "exist. - [%s]",
                      strName.c_str(),
                      drv["path-driver"].get<std::string>().c_str());
                }
            }
        }
        else {
            spdlog::debug(
              "ReadConfig: 'drivers.level2' array missing or invalid.");
        }
    }
    else {
        spdlog::debug("ReadConfig: 'drivers' object missing or invalid; no "
                      "drivers loaded.");
    }

    return true;
} // JSON config

///////////////////////////////////////////////////////////////////////////////
//                              Worker threads
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// clientMsgWorkerThread
//
// Is there any messages to send from Level II clients. Send it/them to all
// devices/clients except for itself.
//

void*
clientMsgWorkerThread(void* userdata)
{
    std::list<vscpEvent*>::iterator it;
    vscpEvent* pev = NULL;

    // Must be a valid control object pointer
    CControlObject* pObj = (CControlObject*)userdata;
    if (NULL == pObj) {
        spdlog::error("clientMsgWorkerThread: Invalid control object pointer. "
                      "Terminating clientMsgWorkerThread");
        return NULL;
    }

    // Work on until told to quit
    while (!pObj->shouldClientWorkerThreadQuit()) {

        // Wait for event
        if (!pObj->getClientList().waitEventInMainReceiveQueue(100)) {
            continue;
        }

        // Get event
        if (NULL ==
            (pev = pObj->getClientList().getEventFromOutputQueue(true))) {
            spdlog::error("clientMsgWorkerThread: No event in output queue (semaphore sinaled it was triggered but queue was empty).");
            continue;
        }

        // Send event to all Level II clients (not to ourselves)
        pObj->getClientList().sendEventAllClients(pev, pev->obid);

        // Delete the event - we are done with it
        vscp_deleteEvent_v2(&pev);

    } // while

    return NULL;
}