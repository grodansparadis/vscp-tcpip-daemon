// tcpipsrv.cpp
//
// This file is part of the VSCP (https://www.vscp.org)
//
// The MIT License (MIT)
//
// Copyright (C) 2000-2026 Ake Hedman, Grodans Paradis AB
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
// https://wiki.openssl.org/index.php/Simple_TLS_Server
// https://wiki.openssl.org/index.php/SSL/TLS_Client
// https://stackoverflow.com/questions/3919420/tutorial-on-using-openssl-with-pthreads
//

#include <list>
#include <new>
#include <string>

#include <arpa/inet.h>
#include <canal-macro.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef WITH_WRAP
#include <tcpd.h>
#endif

#ifndef DWORD
#define DWORD unsigned long
#endif

#include "mongoose.h"
#include "spdlog/spdlog.h"

#include <guid.h>
#include <vscp-guid-parser.h>
#include <vscp.h>
#include <vscpdatetime.h>
#include <vscphelper.h>

#include "controlobject.h"
#include "vscp-binary-protocol.h"
#include "tcpipsrv.h"
#include "version.h"

extern CControlObject* gpobj;

#if defined(__linux__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#elif defined(__APPLE__)
#include <string.h>
#else
// Fallback implementation for Windows or other platforms lacking memmem
#include <string.h>

void*
memmem(const void* haystack,
       size_t haystacklen,
       const void* needle,
       size_t needlelen)
{
    if (needlelen == 0)
        return (void*)haystack;
    if (haystacklen < needlelen)
        return NULL;

    const char* h = (const char*)haystack;
    const char* n = (const char*)needle;

    // Simple O(N*M) search loop
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        if (h[i] == n[0] && memcmp(&h[i], n, needlelen) == 0) {
            return (void*)&h[i];
        }
    }
    return NULL;
}
#endif

#define TCPIPSRV_INACTIVITY_TIMOUT (3600 * 12)

// trim from start
// static inline std::string&
// ltrim(std::string& s)
// {
//     s.erase(s.begin(),
//             std::find_if(s.begin(),
//                          s.end(),
//                          std::not1(std::ptr_fun<int, int>(std::isspace))));
//     return s;
// }

// // trim from end
// static inline std::string&
// rtrim(std::string& s)
// {
//     s.erase(std::find_if(s.rbegin(),
//                          s.rend(),
//                          std::not1(std::ptr_fun<int, int>(std::isspace)))
//               .base(),
//             s.end());
//     return s;
// }

static void
processMainReceiveQueue(CTcpipSrv* server)
{
    CClientList& clientList = server->getControlObject()->getClientList();
    // Limit each pass to the current queue size so producers cannot starve I/O.
    for (size_t remaining = clientList.getMainReceiveQueueSize();
         remaining > 0 && server->isWorking();
         --remaining) {
        if (-1 == clientList.waitForClientMainReceiveQueueEvent(0)) {
            if (errno == ETIMEDOUT || errno == EAGAIN) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            spdlog::error("TCP/IP timer: error waiting for receive queue event: {}",
                          strerror(errno));
            break;
        }

        vscpEvent* pev = clientList.getEventFromClientMainReceiveQueue(true);
        if (nullptr == pev) {
            spdlog::error("TCP/IP timer: receive queue signaled but empty");
            break;
        }

        clientList.sendEventAllClients(pev, pev->obid);
        vscp_deleteEvent_v2(&pev);
    }
}

static void
timer_fn(void* arg)
{
    auto* mgr = static_cast<struct mg_mgr*>(arg);
    auto* server = static_cast<CTcpipSrv*>(mgr->userdata);
    if (nullptr == server || nullptr == server->getControlObject()) {
        spdlog::error("TCP/IP timer: missing server or control object");
        return;
    }

    // Startup backlog and failed wakeups still get a retry.
    processMainReceiveQueue(server);

    // iterate through all active connections
    for (struct mg_connection* conn = mgr->conns; conn != NULL;
         conn                       = conn->next) {

        if (conn->is_listening) {
            continue;
        }

        // Get client item
        CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);
        if (NULL == pClientItem) {
            continue;
        }

        if (pClientItem->isBinaryMode() &&
            pClientItem->getBinaryLoginDeadline() != 0 &&
            mg_millis() >= pClientItem->getBinaryLoginDeadline()) {
            server->writeBinaryReply(conn, 3, VSCP_ERROR_NOT_AUTHORIZED);
            pClientItem->setBinaryLoginDeadline(0);
            conn->is_draining = 1;
            continue;
        }

        // Get timestamp current
        uint32_t currentTimestamp = vscp_getMsTimeStamp();
        bool test                 = pClientItem->isReceiveLoopActive();
        if (pClientItem->isReceiveLoopActive() &&
            (currentTimestamp - pClientItem->getActivityTimestamp() > 1000)) {
            pClientItem->setActivityTimestamp(currentTimestamp);
            if (pClientItem->isBinaryMode()) {
                server->writeBinaryReply(conn, 0, VSCP_ERROR_SUCCESS);
            }
            else {
                mg_send(conn, "+OK\r\n", 5);
            }
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// CTcpipSrv
//
// This thread listens for connection on a TCP socket and starts a new thread
// to handle client requests
//

CTcpipSrv::CTcpipSrv(CControlObject* obj)
{
    m_pCtrlObj = obj;  // Set the control object pointer
    m_bRun     = true; // Not quitting yet

    // Default TCP/IP interface settings
    m_interfaceAddress = "tcp://localhost:9598";

    // No TLS by default
    memset(&m_tcpip_tls_opts, 0, sizeof(m_tcpip_tls_opts));
}

CTcpipSrv::~CTcpipSrv()
{
    spdlog::debug(
      "CTcpipSrv: Joining client thread and clearing command array");

    pthread_join(m_tcpipClientThread, NULL);

    // Remove all clients
    m_pCtrlObj->getClientList().removeAllClients();
}

///////////////////////////////////////////////////////////////////////////////
// write
//

bool
CTcpipSrv::write(struct mg_connection* conn, std::string& str, bool bAddCRLF)
{
    // Check that conn is valid
    if (NULL == conn) {
        spdlog::info("Connection is NULL.");
        return false;
    }

    // Client item must be available
    if (NULL == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return false;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error("write: Client is not connected, cannot write data.");
        return false;
    }

    if (bAddCRLF) {
        str += std::string("\r\n");
    }

    return write(conn, str.data(), str.size());
}

///////////////////////////////////////////////////////////////////////////////
// write
//

bool
CTcpipSrv::write(struct mg_connection* conn, const char* buf, size_t len)
{
    // Check that conn is valid
    if (NULL == conn) {
        spdlog::info("Connection is NULL.");
        return false;
    }

    // Client item must be available
    if (NULL == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return false;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error("Client is not connected, cannot write data.");
        return false;
    }

    if (pClientItem->isBinaryMode()) {
        bool success = len >= 3 && std::string(buf, 3) == "+OK";
        return writeBinaryReply(conn, pClientItem->getBinaryCommand(),
                                 success ? VSCP_ERROR_SUCCESS :
                                           VSCP_ERROR_NOT_AUTHORIZED);
    }

    if (!mg_send(conn, buf, len)) {
        spdlog::error("TCP/IP write: failed to append data to connection");
        return false;
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// commandStartWith
//

bool
CTcpipSrv::commandStartsWith(const std::string& cmd, bool bFix)
{
    if (!vscp_startsWith(vscp_upper(m_currentCommand), vscp_upper(cmd))) {
        return false;
    }

    // If asked to do so remove the command. Only happens on match
    if (bFix) {
        if (m_currentCommand.length() - cmd.length()) {
            m_currentCommand =
              vscp_str_right(m_currentCommand,
                             m_currentCommand.length() - cmd.length() - 1);
        }
        else {
            m_currentCommand.clear();
        }
        vscp_trim(m_currentCommand);
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// commandHandler
//

int
CTcpipSrv::commandHandler(struct mg_connection* conn,
                          const std::string& strCommand)
{
    // Must have a valid connection
    if (NULL == conn) {
        spdlog::error("Connection pointer is NULL, cannot handle command.");
        return -1;
    }

    // Client item must be available
    if (NULL == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return VSCP_ERROR_NOT_CONNECTED;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Get user item (can be NULL if not logged in)
    auto pUserItem = pClientItem->getUserItem();

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error("Client is not connected, cannot handle command.");
        return VSCP_ERROR_NOT_CONNECTED;
    }

    if (NULL == m_pCtrlObj) {
        spdlog::error("[TCP/IP srv] ERROR: Control object pointer is NULL in "
                      "command handler.");
        conn->is_draining = 1;
        return VSCP_ERROR_INTERNAL; // Close connection
    }

    setCurrentCommand(strCommand);

    // If nothing to handle just return
    if (0 == getCurrentCommand().length()) {
        write(conn, MSG_OK, strlen(MSG_OK));
        return VSCP_ERROR_SUCCESS;
    }

    //*********************************************************************
    //                            No Operation
    //*********************************************************************

    if (commandStartsWith("noop", true)) {
        write(conn, MSG_OK, strlen(MSG_OK));
        return VSCP_ERROR_SUCCESS;
    }

    else if (vscp_upper(getCurrentCommand()) == "BINARY") {
        // The transition acknowledgement is the last text response.
        if (write(conn, MSG_OK, sizeof(MSG_OK) - 1)) {
            pClientItem->setBinaryMode(true);
            pClientItem->setBinaryEncryption(0);
            pClientItem->setBinaryPartialSince(0);
            pClientItem->setBinaryResyncing(false);
        }
        return VSCP_ERROR_SUCCESS;
    }

    //*********************************************************************
    //                             Rcvloop
    //*********************************************************************

    else if (commandStartsWith("rcvloop", true) ||
             commandStartsWith("receiveloop", true)) {
        if ((pUserItem != nullptr) &&
            pUserItem->isUserAllowed(VSCP_USER_RIGHT_ALLOW_RCV_EVENT)) {
            try {
                pClientItem->setActivityTimestamp(vscp_getMsTimeStamp());
                handleClientRcvLoop(conn);
            }
            catch (...) {
                spdlog::error("TCPIP: Exception occurred handleClientRcvLoop");
            }
        }
        else {
            write(conn, MSG_NO_RIGHTS_ERROR, strlen(MSG_NO_RIGHTS_ERROR));
        }
    }

    //*********************************************************************
    //                             Quitloop
    //*********************************************************************

    else if (commandStartsWith("quitreceiveloop", true) ||
             commandStartsWith("quitrcvloop", true) ||
             commandStartsWith("quitloop", true)) {
        if ((pUserItem != nullptr) &&
            pUserItem->isUserAllowed(VSCP_USER_RIGHT_ALLOW_RCV_EVENT)) {
            try {
                pClientItem->setActivityTimestamp(vscp_getMsTimeStamp());
                handleClientQuitRcvLoop(conn);
            }
            catch (...) {
                spdlog::error(
                  "TCPIP: Exception occurred handleClientQuitRcvLoop");
            }
        }
        else {
            write(conn, MSG_NO_RIGHTS_ERROR, strlen(MSG_NO_RIGHTS_ERROR));
        }
    }

    //*********************************************************************
    //                             Username
    //*********************************************************************

    else if (commandStartsWith("user", true)) {
        try {
            handleClientUser(conn);
        }
        catch (...) {
            spdlog::error("TCPIP: Exception occurred handleClientUser");
        }
    }

    //*********************************************************************
    //                            Password
    //*********************************************************************

    else if (commandStartsWith("pass", true)) {

        try {
            if (!handleClientPassword(conn)) {
                spdlog::error(
                  "[TCP/IP srv] Command: Password. Not authorized.");
                conn->is_draining = 1;
                return VSCP_ERROR_NOT_AUTHORIZED; // Close connection
            }
        }
        catch (...) {
            spdlog::error("TCPIP: Exception occurred handleClientPassword");
        }

        spdlog::debug("[TCP/IP srv] Command: Password. PASS");
    }

    //*********************************************************************
    //                              Challenge
    //*********************************************************************

    else if (commandStartsWith("challenge", true)) {
        try {
            handleChallenge(conn);
        }
        catch (...) {
            spdlog::error("TCPIP: Exception occurred handleChallenge");
        }
    }

    // *********************************************************************
    //                                 QUIT
    // *********************************************************************

    else if (commandStartsWith("quit", true) ||
             commandStartsWith("exit", true)) {
        spdlog::info("[TCP/IP srv] Command: Close.");
        // write(conn, MSG_GOODBY, strlen(MSG_GOODBY));
        mg_send(conn, MSG_GOODBY, strlen(MSG_GOODBY));
        conn->is_draining        = 1; // close after all pending data is sent
        CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);
        if (pClientItem) {
            pClientItem->setOpen(false);
        }
        return VSCP_ERROR_SUCCESS; // Close connection
    }

    //*********************************************************************
    //                              Shutdown
    //*********************************************************************
    else if (commandStartsWith("shutdown", true)) {
        if ((pUserItem != nullptr) &&
            pUserItem->isUserAllowed(VSCP_USER_RIGHT_ALLOW_SHUTDOWN)) {
            try {
                handleClientShutdown(conn);
            }
            catch (...) {
                spdlog::error("TCPIP: Exception occurred handleClientShutdown");
            }
        }
        else {
            write(conn, MSG_NO_RIGHTS_ERROR, strlen(MSG_NO_RIGHTS_ERROR));
        }
    }

    //*********************************************************************
    //                             Send event
    //*********************************************************************

    else if (commandStartsWith("send", true)) {
        if ((pUserItem != nullptr) &&
            pUserItem->isUserAllowed(VSCP_USER_RIGHT_ALLOW_SEND_EVENT)) {
            try {
                handleClientSend(conn);
            }
            catch (...) {
                spdlog::error("TCPIP: Exception occurred handleClientSend");
            }
        }
        else {
            write(conn, MSG_NO_RIGHTS_ERROR, strlen(MSG_NO_RIGHTS_ERROR));
        }
    }

    //*********************************************************************
    //                            Read event
    //*********************************************************************

    else if (commandStartsWith("retr", true) ||
             commandStartsWith("retrieve", true)) {
        if ((pUserItem != nullptr) &&
            pUserItem->isUserAllowed(VSCP_USER_RIGHT_ALLOW_RCV_EVENT)) {
            try {
                handleClientReceive(conn);
            }
            catch (...) {
                spdlog::error("TCPIP: Exception occurred handleClientReceive");
            }
        }
        else {
            write(conn, MSG_NO_RIGHTS_ERROR, strlen(MSG_NO_RIGHTS_ERROR));
        }
    }

    //*********************************************************************
    //                            Data Available
    //*********************************************************************

    else if (commandStartsWith("cdta", true) ||
             commandStartsWith("chkdata", true) ||
             commandStartsWith("checkdata", true)) {
        try {
            handleClientDataAvailable(conn);
        }
        catch (...) {
            spdlog::error(
              "TCPIP: Exception occurred handleClientDataAvailable");
        }
    }

    //*********************************************************************
    //                          Clear input queue
    //*********************************************************************

    else if (commandStartsWith("clra", true) ||
             commandStartsWith("clearall", true) ||
             commandStartsWith("clrall", true)) {
        try {
            handleClientClearInputQueue(conn);
        }
        catch (...) {
            spdlog::error(
              "TCPIP: Exception occurred handleClientClearInputQueue");
        }
    }

    //*********************************************************************
    //                           Get Statistics
    //*********************************************************************

    else if (commandStartsWith("stat", true)) {
        try {
            handleClientGetStatistics(conn);
        }
        catch (...) {
            spdlog::error(
              "TCPIP: Exception occurred handleClientGetStatistics");
        }
    }

    //*********************************************************************
    //                            Get Status
    //*********************************************************************

    else if (commandStartsWith("info", true)) {
        try {
            handleClientGetStatus(conn);
        }
        catch (...) {
            spdlog::error("TCPIP: Exception occurred handleClientGetStatus");
        }
    }

    //*********************************************************************
    //                           Get Channel ID
    //*********************************************************************

    else if (commandStartsWith("chid", true) ||
             commandStartsWith("getchid", true)) {
        try {
            handleClientGetChannelID(conn);
        }
        catch (...) {
            spdlog::error("TCPIP: Exception occurred handleClientGetChannelID");
        }
    }

    //*********************************************************************
    //                          Set Channel GUID
    //*********************************************************************

    else if (commandStartsWith("sgid", true) ||
             commandStartsWith("setguid", true)) {
        if ((pUserItem != nullptr) &&
            pUserItem->isUserAllowed(VSCP_USER_RIGHT_ALLOW_SETGUID)) {
            try {
                handleClientSetChannelGUID(conn);
            }
            catch (...) {
                spdlog::error(
                  "TCPIP: Exception occurred handleClientSetChannelGUID");
            }
        }
        else {
            write(conn, MSG_NO_RIGHTS_ERROR, strlen(MSG_NO_RIGHTS_ERROR));
        }
    }

    //*********************************************************************
    //                          Get Channel GUID
    //*********************************************************************

    else if (commandStartsWith("ggid", true) ||
             commandStartsWith("getguid", true)) {
        try {
            handleClientGetChannelGUID(conn);
        }
        catch (...) {
            spdlog::error(
              "TCPIP: Exception occurred handleClientGetChannelGUID");
        }
    }

    //*********************************************************************
    //                           Get Version
    //*********************************************************************

    else if (commandStartsWith("version", true) ||
             commandStartsWith("vers", true)) {
        try {
            handleClientGetVersion(conn);
        }
        catch (...) {
            spdlog::error("TCPIP: Exception occurred handleClientGetVersion");
        }
    }

    //*********************************************************************
    //                           Set Filter
    //*********************************************************************

    else if (commandStartsWith("sflt", true) ||
             commandStartsWith("setfilter", true)) {
        if ((pUserItem != nullptr) &&
            pUserItem->isUserAllowed(VSCP_USER_RIGHT_ALLOW_SETFILTER)) {
            try {
                handleClientSetFilter(conn);
            }
            catch (...) {
                spdlog::error(
                  "TCPIP: Exception occurred handleClientSetFilter");
            }
        }
        else {
            write(conn, MSG_NO_RIGHTS_ERROR, strlen(MSG_NO_RIGHTS_ERROR));
        }
    }

    //*********************************************************************
    //                           Set Mask
    //*********************************************************************

    else if (commandStartsWith("smsk", true) ||
             commandStartsWith("setmask", true)) {
        if ((pUserItem != nullptr) &&
            pUserItem->isUserAllowed(VSCP_USER_RIGHT_ALLOW_SETFILTER)) {
            try {
                handleClientSetMask(conn);
            }
            catch (...) {
                spdlog::error("TCPIP: Exception occurred handleClientSetMask");
            }
        }
        else {
            write(conn, MSG_NO_RIGHTS_ERROR, strlen(MSG_NO_RIGHTS_ERROR));
        }
    }

    //*********************************************************************
    //                             Help
    //*********************************************************************

    else if (commandStartsWith("help", true)) {
        try {
            handleClientHelp(conn);
        }
        catch (...) {
            spdlog::error("TCPIP: Exception occurred handleClientHelp");
        }
    }

    //*********************************************************************
    //                             Restart
    //*********************************************************************

    else if (commandStartsWith("restart", true)) {
        if ((pUserItem != nullptr) &&
            pUserItem->isUserAllowed(VSCP_USER_RIGHT_ALLOW_RESTART)) {
            try {
                handleClientRestart(conn);
            }
            catch (...) {
                spdlog::error("TCPIP: Exception occurred handleClientRestart");
            }
        }
        else {
            write(conn, MSG_NO_RIGHTS_ERROR, strlen(MSG_NO_RIGHTS_ERROR));
        }
    }

    //*********************************************************************
    //                         Client/interface
    //*********************************************************************

    else if (commandStartsWith("client", true) ||
             commandStartsWith("interface", true)) {
        if ((pUserItem != nullptr) &&
            pUserItem->isUserAllowed(VSCP_USER_RIGHT_ALLOW_INTERFACE)) {
            try {
                handleClientInterface(conn);
            }
            catch (...) {
                spdlog::error(
                  "TCPIP: Exception occurred handleClientInterface");
            }
        }
        else {
            write(conn, MSG_NO_RIGHTS_ERROR, strlen(MSG_NO_RIGHTS_ERROR));
        }
    }

    //*********************************************************************
    //                               Test
    //*********************************************************************

    else if (commandStartsWith("test", true)) {
        if ((pUserItem != nullptr) &&
            pUserItem->isUserAllowed(VSCP_USER_RIGHT_ALLOW_TEST)) {
            try {
                handleClientTest(conn);
            }
            catch (...) {
                spdlog::error("TCPIP: Exception occurred handleClientTest");
            }
        }
        else {
            write(conn, MSG_NO_RIGHTS_ERROR, strlen(MSG_NO_RIGHTS_ERROR));
        }
    }

    //*********************************************************************
    //                             WhatCanYouDo
    //*********************************************************************

    else if (commandStartsWith("wcyd", true) ||
             commandStartsWith("whatcanyoudo", true)) {
        try {
            handleClientCapabilityRequest(conn);
        }
        catch (...) {
            spdlog::error(
              "TCPIP: Exception occurred handleClientCapabilityRequest");
        }
    }

    //*********************************************************************
    //                             Measurement
    //*********************************************************************

    else if (commandStartsWith("measurement", true)) {
        try {
            handleClientMeasurement(conn);
        }
        catch (...) {
            spdlog::error("TCPIP: Exception occurred handleClientMeasurement");
        }
    }

    //*********************************************************************
    //                                What?
    //*********************************************************************
    else {
        write(conn, MSG_UNKNOWN_COMMAND, strlen(MSG_UNKNOWN_COMMAND));
    }

    setLastCommand(getCurrentCommand());
    return VSCP_ERROR_SUCCESS;

} // commandHandler

bool
CTcpipSrv::writeBinaryFrame(struct mg_connection* conn,
                           std::vector<uint8_t> frame)
{
    auto* client = static_cast<CClientItem*>(conn->fn_data);
    std::vector<uint8_t> wire;
    if (!vscp_binary::encode(std::move(frame), client->getBinaryEncryption(),
                             m_pCtrlObj->getSystemKey(nullptr), wire) ||
        !mg_send(conn, wire.data(), wire.size())) {
        spdlog::error("TCP/IP binary: failed to serialize or send frame");
        conn->is_closing = 1;
        return false;
    }
    return true;
}

bool
CTcpipSrv::writeBinaryReply(struct mg_connection* conn,
                           uint16_t command,
                           uint16_t error,
                           const std::vector<uint8_t>& arguments)
{
    std::vector<uint8_t> frame(7 + arguments.size(), 0);
    if (VSCP_ERROR_SUCCESS != vscp_writeReplyToFrame(
          frame.data(), frame.size(), command, error,
          arguments.empty() ? nullptr : arguments.data(), arguments.size())) {
        spdlog::error("TCP/IP binary: failed to build reply");
        conn->is_closing = 1;
        return false;
    }
    vscp_binary::setCrc(frame);
    return writeBinaryFrame(conn, std::move(frame));
}

uint16_t
CTcpipSrv::enqueueBinaryEvent(struct mg_connection* conn,
                              const std::vector<uint8_t>& frame)
{
    auto* client = static_cast<CClientItem*>(conn->fn_data);
    auto user = client->getUserItem();
    if (!client->isAuthenticated() || !user ||
        !user->isUserAllowed(VSCP_USER_RIGHT_ALLOW_SEND_EVENT)) {
        return VSCP_ERROR_NOT_AUTHORIZED;
    }
    if (frame.size() < 38 || (frame[0] >> 4) > 1 ||
        vscp_binary::read16(frame.data() + 34) > VSCP_MAX_DATA ||
        frame.size() != 38u + vscp_binary::read16(frame.data() + 34)) {
        return VSCP_ERROR_PARAMETER;
    }
    vscpEvent* event = nullptr;
    if (!vscp_newEvent(&event)) {
        return VSCP_ERROR_MEMORY;
    }
    if (!vscp_getEventFromFrame(event, frame.data(), frame.size())) {
        vscp_deleteEvent_v2(&event);
        return VSCP_ERROR_PARAMETER;
    }
    bool allowed = user->isUserAllowedToSendEvent(event->vscp_class,
                                                 event->vscp_type);
    if (event->vscp_class == VSCP_CLASS1_PROTOCOL) {
        allowed = allowed &&
          user->isUserAllowed(VSCP_USER_RIGHT_ALLOW_SEND_L1CTRL_EVENT);
    }
    if (event->vscp_class == VSCP_CLASS2_PROTOCOL) {
        allowed = allowed &&
          user->isUserAllowed(VSCP_USER_RIGHT_ALLOW_SEND_L2CTRL_EVENT);
    }
    if (event->vscp_class == VSCP_CLASS2_HLO) {
        allowed = allowed &&
          user->isUserAllowed(VSCP_USER_RIGHT_ALLOW_SEND_HLO_EVENT);
    }
    if (!allowed) {
        vscp_deleteEvent_v2(&event);
        return VSCP_ERROR_NOT_AUTHORIZED;
    }
    event->obid = client->getClientID();
    if (vscp_isGUIDEmpty(event->GUID)) {
        client->getInterfaceGUID().writeGUID(event->GUID);
    }
    size_t size = event->sizeData;
    if (!m_pCtrlObj->getClientList().enqueueReceiveEvent(event)) {
        vscp_deleteEvent_v2(&event);
        return VSCP_ERROR_FIFO_FULL;
    }
    client->getStatistics().cntReceiveFrames++;
    client->getStatistics().cntReceiveData += size;
    return VSCP_ERROR_SUCCESS;
}

void
CTcpipSrv::handleBinaryFrame(struct mg_connection* conn,
                            const std::vector<uint8_t>& frame)
{
    using vscp_binary::append;
    using vscp_binary::read16;
    auto* client = static_cast<CClientItem*>(conn->fn_data);
    uint8_t type = frame[0] >> 4;
    if (type <= 1) {
        std::vector<uint8_t> confirmation;
        append(confirmation, read16(frame.data() + 1), 4);
        append(confirmation, read16(frame.data() + frame.size() - 2), 2);
        writeBinaryReply(conn, 0xffff, enqueueBinaryEvent(conn, frame),
                         confirmation);
        return;
    }
    if (type == 15 && frame.size() == 13 &&
        read16(frame.data() + 1) == 0xffff) {
        if (read16(frame.data() + 3) != VSCP_ERROR_SUCCESS) {
            spdlog::warn("TCP/IP binary: client reported event delivery failure");
        }
        return;
    }
    if (type != 14 || frame.size() < 5) {
        spdlog::error("TCP/IP binary: unexpected frame type");
        writeBinaryReply(conn, 0xffff, VSCP_ERROR_PARAMETER);
        return;
    }

    uint16_t command = read16(frame.data() + 1);
    client->setBinaryCommand(command);
    const uint8_t* arg = frame.data() + 3;
    size_t length = frame.size() - 5;
    auto user = client->getUserItem();
    uint32_t right = 0;
    switch (command) {
        case 5: right = VSCP_USER_RIGHT_ALLOW_SEND_EVENT; break;
        case 6: case 7: case 8: right = VSCP_USER_RIGHT_ALLOW_RCV_EVENT; break;
        case 14: right = VSCP_USER_RIGHT_ALLOW_SETGUID; break;
        case 17: case 18: right = VSCP_USER_RIGHT_ALLOW_SETFILTER; break;
        case 19: right = VSCP_USER_RIGHT_ALLOW_INTERFACE; break;
        case 20: right = VSCP_USER_RIGHT_ALLOW_TEST; break;
        case 22: right = VSCP_USER_RIGHT_ALLOW_SHUTDOWN; break;
        case 23: right = VSCP_USER_RIGHT_ALLOW_RESTART; break;
    }
    bool publicCommand = command <= 4 || command == 16 ||
                         command == 21 || command == 24;
    if (!publicCommand &&
        (!client->isAuthenticated() || !user ||
         (right && !user->isUserAllowed(right)))) {
        writeBinaryReply(conn, command, VSCP_ERROR_NOT_AUTHORIZED);
        return;
    }

    uint16_t error = VSCP_ERROR_SUCCESS;
    uint16_t replyCommand = command;
    std::vector<uint8_t> reply;
    switch (command) {
        case 0: case 1: case 4: case 7: case 8: case 9: case 10:
        case 11: case 12: case 13: case 15: case 16: case 22: case 23: case 24:
            if (length != 0) {
                writeBinaryReply(conn, command, VSCP_ERROR_PARAMETER);
                return;
            }
            break;
        default: break;
    }
    switch (command) {
        case 0: break;
        case 1:
            conn->is_draining = 1;
            client->setReceiveLoop(false);
            break;
        case 2: {
            std::string credentials(reinterpret_cast<const char*>(arg), length);
            size_t colon = credentials.find(':');
            std::string username = credentials.substr(0, colon);
            if (username.empty() || username.size() > 64 ||
                credentials.find('\0') != std::string::npos ||
                (colon != std::string::npos &&
                 credentials.size() - colon - 1 > 64)) {
                error = VSCP_ERROR_PARAMETER;
                break;
            }
            client->resetAuthentication();
            client->setReceiveLoop(false);
            client->setUserItem(m_pCtrlObj->getUserList().getUser(username.c_str()));
            client->setBinaryLoginDeadline(mg_millis() + 30000);
            if (colon != std::string::npos) {
                setCurrentCommand(credentials.substr(colon + 1));
                bool authenticated = handleClientPassword(conn);
                client->setBinaryLoginDeadline(0);
                if (!authenticated) conn->is_draining = 1;
                return;
            }
            break;
        }
        case 3:
            if (length == 0 || length > 64 ||
                std::find(arg, arg + length, 0) != arg + length) {
                error = VSCP_ERROR_PARAMETER;
                break;
            }
            setCurrentCommand(std::string(reinterpret_cast<const char*>(arg), length));
            {
                bool hadUser = client->getUserItem() != nullptr ||
                               client->getBinaryLoginDeadline() != 0;
                if (!handleClientPassword(conn) && hadUser) {
                    conn->is_draining = 1;
                }
                client->setBinaryLoginDeadline(0);
                return;
            }
        case 4: {
            uint8_t random[16];
            mg_random(random, sizeof(random));
            const char* hex = "0123456789abcdef";
            for (uint8_t byte : random) {
                reply.push_back(hex[byte >> 4]);
                reply.push_back(hex[byte & 15]);
            }
            client->setSessionId(std::string(reply.begin(), reply.end()));
            break;
        }
        case 5: {
            if (length < 35 || length != 35u + read16(arg + 33)) {
                error = VSCP_ERROR_PARAMETER;
                break;
            }
            std::vector<uint8_t> event{0x10};
            event.insert(event.end(), arg, arg + length);
            event.resize(event.size() + 2);
            vscp_binary::setCrc(event);
            error = enqueueBinaryEvent(conn, event);
            break;
        }
        case 6: {
            if ((length != 0 && length != 2) || client->isReceiveLoopActive()) {
                error = client->isReceiveLoopActive() ?
                          VSCP_ERROR_UNSUPPORTED : VSCP_ERROR_PARAMETER;
                break;
            }
            size_t count = length ? read16(arg) : 1;
            if (count == 0) count = 1;
            size_t sent = 0;
            while (sent < count) {
                vscpEvent* event = client->getEventFromSendQueue();
                if (!event) break;
                std::vector<uint8_t> encoded(vscp_getFrameSizeFromEvent(event), 0);
                bool ok = vscp_writeEventToFrame(encoded.data(), encoded.size(),
                                                 0, event);
                vscp_deleteEvent_v2(&event);
                if (!ok) {
                    spdlog::error("TCP/IP binary: failed to serialize queued event");
                    error = VSCP_ERROR_INTERNAL;
                    break;
                }
                std::vector<uint8_t> body(encoded.begin() + 1, encoded.end() - 2);
                if (!writeBinaryReply(conn, command, VSCP_ERROR_SUCCESS, body)) return;
                ++sent;
            }
            if (error == VSCP_ERROR_SUCCESS && sent) return;
            if (!sent && error == VSCP_ERROR_SUCCESS) error = VSCP_ERROR_RCV_EMPTY;
            break;
        }
        case 7: case 8:
            client->setReceiveLoop(command == 7);
            client->setActivityTimestamp(vscp_getMsTimeStamp());
            break;
        case 9:
            append(reply, client->isReceiveLoopActive() ? 0 :
                            client->getClientSendQueueSize(), 4);
            break;
        case 10:
            if (!client->isReceiveLoopActive()) client->clearSendQueue();
            break;
        case 11: {
            auto& stats = client->getStatistics();
            append(reply, 0, 4); append(reply, 0, 4); append(reply, 0, 4);
            append(reply, stats.cntReceiveData, 4);
            append(reply, stats.cntReceiveFrames, 4);
            append(reply, stats.cntTransmitData, 4);
            append(reply, stats.cntTransmitFrames, 4);
            append(reply, stats.cntOverruns, 4);
            break;
        }
        case 12: {
            auto& status = client->getStatus();
            append(reply, status.channel_status, 4);
            append(reply, status.lasterrorcode, 4);
            append(reply, status.lasterrorsubcode, 4);
            size_t count = 0;
            while (count < 79 && status.lasterrorstr[count]) {
                reply.push_back(status.lasterrorstr[count++]);
            }
            reply.push_back(0);
            break;
        }
        case 13: append(reply, client->getClientID(), 4); break;
        case 14:
            if (length != 16) error = VSCP_ERROR_PARAMETER;
            else {
                cguid guid;
                guid.getFromArray(arg);
                client->setInterfaceGUID(guid);
            }
            break;
        case 15: {
            auto guid = client->getInterfaceGUID();
            reply.assign(guid.getGUID(), guid.getGUID() + 16);
            break;
        }
        case 16:
            append(reply, VSCPD_VERSION_MAJOR, 2);
            append(reply, VSCPD_VERSION_MINOR, 2);
            append(reply, VSCPD_VERSION_PATCH, 2);
            append(reply, 0, 4);
            break;
        case 17: case 18: {
            if ((command == 17 && length != 21 && length != 42) ||
                (command == 18 && length != 21) || arg[0] > 7 ||
                (length == 42 && arg[21] > 7)) {
                error = VSCP_ERROR_PARAMETER;
                break;
            }
            auto& filter = client->getFilter();
            if (command == 17) {
                filter.filter_priority = arg[0];
                filter.filter_class = read16(arg + 1);
                filter.filter_type = read16(arg + 3);
                std::copy(arg + 5, arg + 21, filter.filter_GUID);
            }
            if (command == 18 || length == 42) {
                const uint8_t* mask = arg + (command == 18 ? 0 : 21);
                filter.mask_priority = mask[0];
                filter.mask_class = read16(mask + 1);
                filter.mask_type = read16(mask + 3);
                std::copy(mask + 5, mask + 21, filter.mask_GUID);
            }
            break;
        }
        case 19: {
            if ((length != 1 && length != 3) || arg[0] > 3 ||
                (arg[0] == 0 ? length != 1 : length != 3)) {
                error = VSCP_ERROR_PARAMETER;
                break;
            }
            replyCommand = command + arg[0];
            auto& list = m_pCtrlObj->getClientList();
            list.lockClientItemList();
            auto& items = list.getItemList();
            if (arg[0] == 0) append(reply, items.size(), 2);
            else {
                uint16_t index = read16(arg + 1);
                if (index >= items.size()) error = VSCP_ERROR_PARAMETER;
                else {
                    auto* item = items[index];
                    append(reply, index, 2);
                    if (arg[0] == 1) {
                        auto interfaceGuid = item->getInterfaceGUID();
                        const uint8_t* guid = interfaceGuid.getGUID();
                        reply.insert(reply.end(), guid, guid + 16);
                        std::string name = item->getDeviceName();
                        reply.insert(reply.end(), name.begin(),
                                     name.begin() + std::min<size_t>(63, name.size()));
                        reply.resize(82, 0);
                    }
                    else item->setOpen(arg[0] == 3);
                }
            }
            list.unlockClientItemList();
            break;
        }
        case 21:
            if (length != 0 && length != 8) error = VSCP_ERROR_PARAMETER;
            else {
                uint8_t capabilities[8];
                if (!m_pCtrlObj->getVscpCapabilities(capabilities)) {
                    error = VSCP_ERROR_INTERNAL;
                }
                else reply.assign(std::rbegin(capabilities), std::rend(capabilities));
            }
            break;
        case 22: case 23:
            if (!writeBinaryReply(conn, command, error)) return;
#ifdef WIN32
            m_pCtrlObj->m_bQuit = true;
#else
            kill(getpid(), command == 22 ? SIGUSR1 : SIGUSR2);
#endif
            return;
        case 24:
            if (writeBinaryReply(conn, command, VSCP_ERROR_SUCCESS)) {
                client->setBinaryMode(false);
                client->setBinaryEncryption(0);
                client->setBinaryLoginDeadline(0);
            }
            return;
        default:
            error = VSCP_ERROR_UNSUPPORTED;
            break;
    }
    if (error != VSCP_ERROR_SUCCESS) {
        spdlog::warn("TCP/IP binary: command {} failed with error {}", command, error);
        reply.clear();
    }
    writeBinaryReply(conn, replyCommand, error, reply);
}

void
CTcpipSrv::discardBinaryInput(struct mg_connection* conn, size_t count)
{
    auto* client = static_cast<CClientItem*>(conn->fn_data);
    mg_iobuf_del(&conn->recv, 0, count);
    client->setBinaryPartialSince(0);
    if (!client->isBinaryResyncing()) {
        client->setBinaryResyncing(true);
        spdlog::warn("TCP/IP binary: invalid data, searching for next frame");
        writeBinaryReply(conn, 0xffff, VSCP_ERROR_INVALID_FRAME);
    }
}

void
CTcpipSrv::checkBinaryReceiveTimeout(struct mg_connection* conn, uint64_t now)
{
    auto* client = static_cast<CClientItem*>(conn->fn_data);
    if (!client || !client->isBinaryMode() || !conn->recv.len ||
        conn->is_closing) {
        return;
    }
    uint64_t since = client->getBinaryPartialSince();
    if (since && now - since >= vscp_binary::partialFrameTimeoutMs) {
        spdlog::warn("TCP/IP binary: incomplete frame timed out");
        discardBinaryInput(conn, 1);
        handleIncomingData(conn);
    }
}

void
CTcpipSrv::handleIncomingData(struct mg_connection* conn)
{
    auto* client = static_cast<CClientItem*>(conn->fn_data);
    if (!client) {
        spdlog::error("TCP/IP input: missing client");
        conn->is_closing = 1;
        return;
    }
    auto& input = conn->recv;
    while (input.len && !conn->is_closing && !conn->is_draining) {
        if (client->isBinaryMode()) {
            if (input.buf[0] != vscp_binary::syncByte) {
                auto* sync = static_cast<uint8_t*>(
                  memchr(input.buf, vscp_binary::syncByte, input.len));
                discardBinaryInput(conn, sync ? sync - input.buf : input.len);
                continue;
            }
            if (input.len < vscp_binary::headerSize + 1) return;
            size_t length = 0;
            if (!vscp_binary::parseHeader(input.buf, length)) {
                discardBinaryInput(conn, 1);
                continue;
            }
            if (input.len < length + vscp_binary::headerSize) {
                if (!client->getBinaryPartialSince()) {
                    client->setBinaryPartialSince(mg_millis());
                }
                return;
            }
            std::vector<uint8_t> wire(input.buf + vscp_binary::headerSize,
                                      input.buf + vscp_binary::headerSize + length);
            std::vector<uint8_t> frame;
            if (!vscp_binary::decode(std::move(wire),
                                     m_pCtrlObj->getSystemKey(nullptr), frame)) {
                // The length may be corrupt, so search from the next byte.
                discardBinaryInput(conn, 1);
                continue;
            }
            mg_iobuf_del(&input, 0, length + vscp_binary::headerSize);
            client->setBinaryPartialSince(0);
            client->setBinaryResyncing(false);
            client->setBinaryEncryption(frame[0] & 15);
            handleBinaryFrame(conn, frame);
        }
        else {
            auto* eol = static_cast<uint8_t*>(memmem(input.buf, input.len, "\r\n", 2));
            if (!eol) {
                if (input.len >= 2048) {
                    spdlog::error("TCP/IP input: command exceeds line limit");
                    write(conn, MSG_PARAMETER_ERROR, sizeof(MSG_PARAMETER_ERROR) - 1);
                    conn->is_draining = 1;
                }
                return;
            }
            size_t length = eol - input.buf;
            if (length >= 2048) {
                write(conn, MSG_PARAMETER_ERROR, sizeof(MSG_PARAMETER_ERROR) - 1);
                conn->is_draining = 1;
                return;
            }
            std::string line(reinterpret_cast<const char*>(input.buf), length);
            mg_iobuf_del(&input, 0, length + 2);
            commandHandler(conn, line);
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// handleClientMeasurement
//
// format,level,vscp-measurement-type,value,unit,guid,sensoridx,zone,subzone,dest-guid
//
// format                   float|string|0|1 - float=0, string=1.
// level                    level2|1|level1|0  1 = VSCP Level I event, 2 = VSCP
// Level II event. vscp-measurement-type    A valid vscp measurement type. value
// A floating point value. (use $ prefix for variable followed by name) unit
// Optional unit for this type. Default = 0. guid                     Optional
// GUID (or "-"). Default is "-". sensoridx                Optional sensor
// index. Default is 0. zone                     Optional zone. Default is 0.
// subzone                  Optional subzone- Default is 0.
// dest-guid                Optional destination GUID. For Level I over Level
// II.
//

void
CTcpipSrv::handleClientMeasurement(struct mg_connection* conn)
{
    std::string str;
    double value = 0;
    cguid guid;     // Initialized to zero
    cguid destguid; // Initialized to zero
    long level = VSCP_LEVEL2;
    long unit  = 0;
    long vscptype;
    long sensoridx   = 0;
    long zone        = 0;
    long subzone     = 0;
    long eventFormat = 0; // float
    uint8_t data[VSCP_MAX_DATA];
    uint16_t sizeData;

    // Check that conn is valid
    if (NULL == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (NULL == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Check object pointer
    if (NULL == m_pCtrlObj) {
        write(conn,
              MSG_INTERNAL_MEMORY_ERROR,
              strlen(MSG_INTERNAL_MEMORY_ERROR));
        return;
    }

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error("Client is not connected, cannot handle measurement.");
        return;
    }

    std::deque<std::string> tokens;
    vscp_split(tokens, getCurrentCommand(), ",");

    // * * * event format * * *

    // Get event format (float | string | 0 | 1 - float=0, string=1.)
    if (tokens.empty()) {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    str = tokens.front();
    tokens.pop_front();

    vscp_trim(str);
    vscp_makeUpper(str);

    // Handle float=0
    if ('0' == str[0]) {
        eventFormat = 0;
    }
    // Handle string=1
    else if ('1' == str[0]) {
        eventFormat = 1;
    }
    else if (str == "STRING") {
        eventFormat = 1;
    }
    else if (str == "FLOAT") {
        eventFormat = 0;
    }
    else {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    // * * * Level * * *

    if (tokens.empty()) {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    str = tokens.front();
    tokens.pop_front();

    vscp_trim(str);
    vscp_makeUpper(str);

    if ('0' == str[0]) {
        level = VSCP_LEVEL1;
    }
    else if ('1' == str[0]) {
        level = VSCP_LEVEL2;
    }
    else if (str == "LEVEL1") {
        level = VSCP_LEVEL1;
    }
    else if (str == "LEVEL2") {
        level = VSCP_LEVEL2;
    }
    else {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    // * * * vscp-measurement-type * * *
    if (tokens.empty()) {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    str = tokens.front();
    tokens.pop_front();
    vscptype = vscp_readStringValue(str);

    // * * * value * * *
    if (tokens.empty()) {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    str = tokens.front();
    tokens.pop_front();
    vscp_trim(str);

    value = std::stod(str);

    // * * * unit * * *

    if (!tokens.empty()) {
        str = tokens.front();
        tokens.pop_front();
        unit = vscp_readStringValue(str);
    }

    // * * * guid * * *

    if (!tokens.empty()) {

        str = tokens.front();
        tokens.pop_front();
        vscp_trim(str);

        // If empty set to default.
        if (0 == str.length())
            str = "-";
        guid.getFromString(str);
    }

    // * * * sensor index * * *

    if (!tokens.empty()) {
        str = tokens.front();
        tokens.pop_front();
        vscp_trim(str);

        sensoridx = vscp_readStringValue(str);
    }

    // * * * zone * * *

    if (!tokens.empty()) {

        str = tokens.front();
        tokens.pop_front();
        vscp_trim(str);

        zone = vscp_readStringValue(str);
        ;
        zone &= 0xff;
    }

    // * * * subzone * * *

    if (!tokens.empty()) {

        str = tokens.front();
        tokens.pop_front();
        vscp_trim(str);

        subzone = vscp_readStringValue(str);
        subzone &= 0xff;
    }

    // * * * destguid * * *

    if (!tokens.empty()) {

        str = tokens.front();
        tokens.pop_front();
        vscp_trim(str);

        // If empty set to default.
        if (0 == str.length())
            str = ("-");
        destguid.getFromString(str);
    }

    // Range checks
    if (VSCP_LEVEL1 == level) {
        if (unit > 3)
            unit = 0;
        if (sensoridx > 7)
            unit = 0;
        if (vscptype > 512)
            vscptype -= 512;
    }
    else { // VSCP_LEVEL2
        if (unit > 255)
            unit &= 0xff;
        if (sensoridx > 255)
            sensoridx &= 0xff;
    }

    if (1 == level) { // Level I

        if (0 == eventFormat) {

            // * * * Floating point * * *

            if (vscp_convertFloatToFloatEventData(data,
                                                  &sizeData,
                                                  value,
                                                  unit,
                                                  sensoridx)) {
                if (sizeData > 8)
                    sizeData = 8;

                vscpEvent* pEvent = new vscpEvent;
                if (NULL == pEvent) {
                    write(conn,
                          MSG_INTERNAL_MEMORY_ERROR,
                          strlen(MSG_INTERNAL_MEMORY_ERROR));
                    return;
                }

                pEvent->pdata     = NULL;
                pEvent->head      = VSCP_PRIORITY_NORMAL;
                pEvent->timestamp = 0; // Let interface fill in
                                       // Will fill in date/time block also
                guid.writeGUID(pEvent->GUID);
                pEvent->sizeData = sizeData;
                if (sizeData > 0) {
                    pEvent->pdata = new uint8_t[sizeData];
                    memcpy(pEvent->pdata, data, sizeData);
                }
                pEvent->vscp_class = VSCP_CLASS1_MEASUREMENT;
                pEvent->vscp_type  = vscptype;

                // send the event
                if (!m_pCtrlObj->getClientList().enqueueReceiveEvent(pEvent)) {
                    vscp_deleteEvent_v2(&pEvent);
                    write(conn,
                          MSG_UNABLE_TO_SEND_EVENT,
                          strlen(MSG_UNABLE_TO_SEND_EVENT));
                    return;
                }

            }
            else {
                write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
            }
        }
        else {

            // * * * String * * *

            vscpEvent* pEvent = new vscpEvent;
            if (NULL == pEvent) {
                write(conn,
                      MSG_INTERNAL_MEMORY_ERROR,
                      strlen(MSG_INTERNAL_MEMORY_ERROR));
                return;
            }

            pEvent->pdata = NULL;

            if (!vscp_makeStringMeasurementEvent(pEvent,
                                                 value,
                                                 unit,
                                                 sensoridx)) {
                write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
            }

            // send the event
            if (!m_pCtrlObj->getClientList().enqueueReceiveEvent(pEvent)) {
                vscp_deleteEvent_v2(&pEvent);
                write(conn,
                      MSG_UNABLE_TO_SEND_EVENT,
                      strlen(MSG_UNABLE_TO_SEND_EVENT));
                return;
            }

        }
    }
    else { // Level II

        if (0 == eventFormat) { // float and Level II

            // * * * Floating point * * *

            vscpEvent* pEvent = new vscpEvent;
            if (NULL == pEvent) {
                write(conn,
                      MSG_INTERNAL_MEMORY_ERROR,
                      strlen(MSG_INTERNAL_MEMORY_ERROR));
                return;
            }

            pEvent->pdata = NULL;

            pEvent->obid      = 0;
            pEvent->head      = VSCP_PRIORITY_NORMAL;
            pEvent->timestamp = 0; // Let interface fill in timestamp
                                   // Will fill in date/time block also
            guid.writeGUID(pEvent->GUID);
            pEvent->head       = 0;
            pEvent->vscp_class = VSCP_CLASS2_MEASUREMENT_FLOAT;
            pEvent->vscp_type  = vscptype;
            pEvent->sizeData   = 12;

            data[0] = sensoridx;
            data[1] = zone;
            data[2] = subzone;
            data[3] = unit;

            memcpy(data + 4, (uint8_t*)&value, 8); // copy in double
            uint64_t temp = VSCP_UINT64_SWAP_ON_LE(*(data + 4));
            memcpy(data + 4, (void*)&temp, 8);

            // Copy in data
            pEvent->pdata = new uint8_t[4 + 8];
            if (NULL == pEvent->pdata) {
                write(conn,
                      MSG_INTERNAL_MEMORY_ERROR,
                      strlen(MSG_INTERNAL_MEMORY_ERROR));
                delete pEvent;
                return;
            }

            memcpy(pEvent->pdata, data, 4 + 8);

            // send the event
            if (!m_pCtrlObj->getClientList().enqueueReceiveEvent(pEvent)) {
                vscp_deleteEvent_v2(&pEvent);
                write(conn,
                      MSG_UNABLE_TO_SEND_EVENT,
                      strlen(MSG_UNABLE_TO_SEND_EVENT));
                return;
            }

        }
        else { // string & Level II

            // * * * String * * *

            vscpEvent* pEvent = new vscpEvent;
            pEvent->pdata     = NULL;

            pEvent->obid      = 0;
            pEvent->head      = VSCP_PRIORITY_NORMAL;
            pEvent->timestamp = 0; // Let interface fill in
                                   // Will fill in date/time block also
            guid.writeGUID(pEvent->GUID);
            pEvent->head       = 0;
            pEvent->vscp_class = VSCP_CLASS2_MEASUREMENT_STR;
            pEvent->vscp_type  = vscptype;
            pEvent->sizeData   = 12;

            std::string strValue = vscp_str_format("%f", value);

            data[0] = sensoridx;
            data[1] = zone;
            data[2] = subzone;
            data[3] = unit;

            pEvent->pdata = new uint8_t[4 + strValue.length()];
            if (NULL == pEvent->pdata) {
                write(conn,
                      MSG_INTERNAL_MEMORY_ERROR,
                      strlen(MSG_INTERNAL_MEMORY_ERROR));
                delete pEvent;
                return;
            }
            memcpy(data + 4,
                   strValue.c_str(),
                   strValue.length()); // copy in double

            // send the event
            if (!m_pCtrlObj->getClientList().enqueueReceiveEvent(pEvent)) {
                vscp_deleteEvent_v2(&pEvent);
                write(conn,
                      MSG_UNABLE_TO_SEND_EVENT,
                      strlen(MSG_UNABLE_TO_SEND_EVENT));
                return;
            }

        }
    }

    write(conn, MSG_OK, strlen(MSG_OK));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientCapabilityRequest
//

void
CTcpipSrv::handleClientCapabilityRequest(struct mg_connection* conn)
{
    std::string str;
    uint8_t capabilities[8];

    // Check that conn is valid
    if (NULL == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (NULL == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    m_pCtrlObj->getVscpCapabilities(capabilities);
    str = vscp_str_format("%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X\r\n",
                          capabilities[7],
                          capabilities[6],
                          capabilities[5],
                          capabilities[4],
                          capabilities[3],
                          capabilities[2],
                          capabilities[1],
                          capabilities[0]);
    write(conn, str.c_str(), str.length());
    write(conn, MSG_OK, strlen(MSG_OK));
}

///////////////////////////////////////////////////////////////////////////////
// isVerified
//

bool
CTcpipSrv::isVerified(struct mg_connection* conn)
{
    // Check that conn is valid
    if (NULL == conn) {
        spdlog::info("Connection is NULL.");
        return false;
    }

    // Must be connected
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);
    if (NULL == pClientItem) {
        spdlog::error("isVerified: Client item not found for connection id: {}",
                      conn->id);
        return false;
    }

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error("Client is not connected, cannot verify.");
        return false;
    }

    // Get user item (can be NULL if not logged in)
    auto pUserItem = pClientItem->getUserItem();

    // Must be accredited to do this
    if ((nullptr == pUserItem) || !pClientItem->isAuthenticated()) {
        write(conn, MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
        return false;
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// handleClientSend
//

void
CTcpipSrv::handleClientSend(struct mg_connection* conn)
{
    vscpEvent event{};

    // Check that conn is valid
    if (NULL == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (NULL == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Get user item (can be NULL if not logged in)
    auto pUserItem = pClientItem->getUserItem();

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error("Client is not connected, cannot handle client send.");
        return;
    }

    // Set timestamp block for event
    vscp_setEventDateTimeBlockToNow(&event); // TODO - change to UTC

    if (NULL == m_pCtrlObj) {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    // Must be accredited to do this
    if ((nullptr == pUserItem) || !pClientItem->isAuthenticated()) {
        write(conn, MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
        return;
    }

    std::string str;
    std::deque<std::string> tokens;
    vscp_split(tokens, getCurrentCommand(), ",");

    // If first character is $ user request us to send content from
    // a variable

    if (!tokens.empty()) {
        // Get Head
        str = tokens.front();
        tokens.pop_front();
        vscp_trim(str);
        event.head = vscp_readStringValue(str);
    }
    else {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    // Get Class
    if (!tokens.empty()) {
        str = tokens.front();
        tokens.pop_front();
        event.vscp_class = vscp_readStringValue(str);
    }
    else {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    // Get Type
    if (!tokens.empty()) {
        str = tokens.front();
        tokens.pop_front();
        event.vscp_type = vscp_readStringValue(str);
    }
    else {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    // Get OBID  -  Kept here to be compatible with receive
    if (!tokens.empty()) {
        str = tokens.front();
        tokens.pop_front();
        event.obid = vscp_readStringValue(str);
    }
    else {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    // Get date/time - should be empty for events from modern senders
    if (!tokens.empty()) {
        str = tokens.front();
        tokens.pop_front();
        vscp_trim(str);
        if (str.length()) {
            /*
              We set the datettime the old way so we can take care of possible
              timestamp relative timing.
            */
            vscpdatetime dt;
            if (dt.set(str)) {
                event.year   = dt.getYear();
                event.month  = dt.getMonth();
                event.day    = dt.getDay();
                event.hour   = dt.getHour();
                event.minute = dt.getMinute();
                event.second = dt.getSecond();
            }
            else {
                // Failed to parse date/time string, set current date/time
                // instead
                vscp_setEventDateTimeBlockToNow(&event);
            }
        }
        else {
            // Set current timestamp in Unix nanoseconds format
            event.head |= VSCP_HEADER16_FRAME_VERSION_UNIX_NS;
            event.year         = 0xffff;
            event.month        = 0xff;
            event.timestamp_ns = vscp_makeTimeStampNs();
        }
    }
    else {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    /*
        Get (Unix nanosecond) timestamp - can be empty
        (Old type is a regular timestamp in microsecond).
        The old type should be preserved so realtive timing calculations remain
       accurate.
    */
    if (!tokens.empty()) {
        str = tokens.front();
        tokens.pop_front();
        vscp_trim(str);
        if (str.length()) {
            // If the event uses the Unix nanosecond timestamp format, store it
            // in timestamp_ns, otherwise store it in timestamp
            if (VSCP_HEADER16_FRAME_VERSION_UNIX_NS ==
                (event.head & VSCP_HEADER16_FRAME_VERSION_MASK)) {
                // Extra marker to indicate that the timestamp is in Unix
                // nanoseconds format
                event.year         = 0xffff;
                event.month        = 0xff;
                event.timestamp_ns = (uint64_t)vscp_readStringValue(str);
            }
            else {
                event.timestamp = vscp_readStringValue(str);
            }
        }
        else {
            // Set current timestamp in Unix nanoseconds format
            event.head |= VSCP_HEADER16_FRAME_VERSION_UNIX_NS;
            event.year         = 0xffff;
            event.month        = 0xff;
            event.timestamp_ns = vscp_makeTimeStampNs();
        }
    }
    else {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    // Translate all frames so they use the unix nanosecond timestamp format

    if (VSCP_HEADER16_FRAME_VERSION_ORIGINAL ==
        (event.head & VSCP_HEADER16_FRAME_VERSION_MASK)) {

        // Original frame format - convert date/time fields to unix nanoseconds
        // format

        // Set head with UNIX_NS frame version
        event.head |= VSCP_HEADER16_FRAME_VERSION_UNIX_NS;

        event.timestamp_ns = vscp_to_unix_ns(event.year,
                                             event.month,
                                             event.day,
                                             event.hour,
                                             event.minute,
                                             event.second,
                                             event.timestamp);
        event.year         = 0xffff;
        event.month        = 0xff;
    }

    // Get GUID
    std::string strGUID;
    if (!tokens.empty()) {

        strGUID = tokens.front();
        tokens.pop_front();

        // Parse the GUID string into the event's GUID structure
        (void)vscp_parseGuid(event.GUID, strGUID);
    }
    else {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    // Handle data
    if (VSCP_MAX_DATA < tokens.size()) {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    event.sizeData = tokens.size();

    if (event.sizeData > 0) {

        unsigned int index = 0;

        event.pdata = new uint8_t[event.sizeData];

        if (NULL == event.pdata) {
            write(conn,
                  MSG_INTERNAL_MEMORY_ERROR,
                  strlen(MSG_INTERNAL_MEMORY_ERROR));
            return;
        }

        while (!tokens.empty() && (event.sizeData > index)) {
            str = tokens.front();
            tokens.pop_front();
            event.pdata[index++] = vscp_readStringValue(str);
        }

        if (!tokens.empty()) {
            write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));

            delete[] event.pdata;
            event.pdata = NULL;
            return;
        }
    }
    else {
        // No data
        event.pdata = NULL;
    }

    // Check if we are allowed to send CLASS1.PROTOCOL events
    if ((VSCP_CLASS1_PROTOCOL == event.vscp_class) && !(pUserItem != nullptr) &&
        (pUserItem != nullptr) &&
        pUserItem->isUserAllowed(VSCP_USER_RIGHT_ALLOW_SEND_L1CTRL_EVENT)) {

        std::string strErr = vscp_str_format(
          ("[TCP/IP srv] User [%s] not allowed to send event class=%d "
           "type=%d.\n"),
          (const char*)pUserItem->getUserName().c_str(),
          event.vscp_class,
          event.vscp_type);

        spdlog::error("%s", strErr.c_str());

        write(conn,
              MSG_MOT_ALLOWED_TO_SEND_EVENT,
              strlen(MSG_MOT_ALLOWED_TO_SEND_EVENT));

        if (NULL != event.pdata) {
            delete[] event.pdata;
            event.pdata = NULL;
        }

        return;
    }

    // Check if we are allowed top send CLASS1.PROTOCOL events
    if ((VSCP_CLASS1_PROTOCOL == event.vscp_class) && !(pUserItem != nullptr) &&
        (pUserItem != nullptr) &&
        pUserItem->isUserAllowed(VSCP_CLASS2_LEVEL1_PROTOCOL)) {

        std::string strErr = vscp_str_format(
          ("[TCP/IP srv] User [%s] not allowed to send event class=%d "
           "type=%d.\n"),
          (const char*)pUserItem->getUserName().c_str(),
          event.vscp_class,
          event.vscp_type);

        spdlog::error("%s", strErr.c_str());

        write(conn,
              MSG_MOT_ALLOWED_TO_SEND_EVENT,
              strlen(MSG_MOT_ALLOWED_TO_SEND_EVENT));

        if (NULL != event.pdata) {
            delete[] event.pdata;
            event.pdata = NULL;
        }

        return;
    }

    // Check if we are allowed top send CLASS2.PROTOCOL events
    if ((VSCP_CLASS2_PROTOCOL == event.vscp_class) && !(pUserItem != nullptr) &&
        (pUserItem != nullptr) &&
        pUserItem->isUserAllowed(VSCP_USER_RIGHT_ALLOW_SEND_L2CTRL_EVENT)) {

        std::string strErr = vscp_str_format(
          ("[TCP/IP srv] User [%s] not allowed to send event class=%d "
           "type=%d.\n"),
          (const char*)pUserItem->getUserName().c_str(),
          event.vscp_class,
          event.vscp_type);

        spdlog::error("%s", strErr.c_str());

        write(conn,
              MSG_MOT_ALLOWED_TO_SEND_EVENT,
              strlen(MSG_MOT_ALLOWED_TO_SEND_EVENT));

        if (NULL != event.pdata) {
            delete[] event.pdata;
            event.pdata = NULL;
        }

        return;
    }

    // Check if we are allowed top send CLASS2.HLO events
    if ((VSCP_CLASS2_HLO == event.vscp_class) &&
        !pUserItem->isUserAllowedToSendEvent(VSCP_CLASS2_HLO, 0)) {

        std::string strErr = vscp_str_format(
          ("[TCP/IP srv] User [%s] not allowed to send event class=%d "
           "type=%d.\n"),
          (const char*)pUserItem->getUserName().c_str(),
          event.vscp_class,
          event.vscp_type);

        spdlog::error("%s", strErr.c_str());

        write(conn,
              MSG_MOT_ALLOWED_TO_SEND_EVENT,
              strlen(MSG_MOT_ALLOWED_TO_SEND_EVENT));

        if (NULL != event.pdata) {
            delete[] event.pdata;
            event.pdata = NULL;
        }

        return;
    }

    // Check if this user is allowed to send this event
    if (!pUserItem->isUserAllowedToSendEvent(event.vscp_class,
                                             event.vscp_type)) {

        std::string strErr = vscp_str_format(
          ("[TCP/IP srv] User [%s] not allowed to send event class=%d "
           "type=%d.\n"),
          (const char*)pUserItem->getUserName().c_str(),
          event.vscp_class,
          event.vscp_type);

        spdlog::error("%s", strErr.c_str());

        write(conn,
              MSG_MOT_ALLOWED_TO_SEND_EVENT,
              strlen(MSG_MOT_ALLOWED_TO_SEND_EVENT));

        if (NULL != event.pdata) {
            delete[] event.pdata;
            event.pdata = NULL;
        }

        return;
    }

    // If the event has no originator ID, set it to the client ID.
    if (!event.obid) {
        event.obid = pClientItem->getClientID();
    }

    // Transfer the payload to a heap event owned by the queue on success.
    vscpEvent* queuedEvent = new (std::nothrow) vscpEvent(event);
    if (nullptr == queuedEvent) {
        delete[] event.pdata;
        spdlog::error("handleClientSend: unable to allocate queued event");
        write(conn, MSG_INTERNAL_MEMORY_ERROR, sizeof(MSG_INTERNAL_MEMORY_ERROR) - 1);
        return;
    }
    event.pdata = nullptr;

    if (!m_pCtrlObj->getClientList().enqueueReceiveEvent(queuedEvent)) {
        vscp_deleteEvent_v2(&queuedEvent);
        write(conn, MSG_BUFFER_FULL, strlen(MSG_BUFFER_FULL));
        return;
    }

    // Update statistics
    pClientItem->getStatistics().cntReceiveFrames++;
    pClientItem->getStatistics().cntReceiveData += event.sizeData;

    write(conn, MSG_OK, strlen(MSG_OK));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientReceive
//

void
CTcpipSrv::handleClientReceive(struct mg_connection* conn)
{
    unsigned short cnt = 0; // # of messages to read

    // Check that conn is valid
    if (NULL == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (NULL == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Get user item (can be NULL if not logged in)
    auto pUserItem = pClientItem->getUserItem();

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error("Client is not connected, cannot handle client receive.");
        return;
    }

    // Must be accredited to do this
    if ((nullptr == pUserItem) || !pClientItem->isAuthenticated()) {
        write(conn, MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
        return;
    }

    std::string str;
    cnt = vscp_readStringValue(getCurrentCommand());

    if (!cnt) {
        cnt = 1; // No arg is "read one"
    }

    // Read cnt messages
    while (cnt) {

        std::string strOut;

        if (!pClientItem->isOpen()) {
            write(conn, MSG_NO_MSG, strlen(MSG_NO_MSG));
            return;
        }
        else {
            if (false == sendOneEventFromQueue(conn)) {
                return;
            }
        }

        cnt--;

    } // while

    write(conn, MSG_OK, strlen(MSG_OK));
}

///////////////////////////////////////////////////////////////////////////////
// sendOneEventFromQueue
//

bool
CTcpipSrv::sendOneEventFromQueue(struct mg_connection* conn, bool bStatusMsg)
{
    std::string strOut;

    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return false;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return false;
    }
    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error(
          "Client is not connected, cannot send one event from queue.");
        return false;
    }

    if (pClientItem->getClientSendQueueSize() > 0) {

        // Get event
        vscpEvent* pev = pClientItem->getEventFromSendQueue(true);
        if (nullptr == pev) {
            spdlog::error("sendOneEventFromQueue: Failed to get event from "
                          "client input queue.");
            return false;
        }

        bool sent;
        if (pClientItem->isBinaryMode()) {
            std::vector<uint8_t> frame(vscp_getFrameSizeFromEvent(pev), 0);
            if (!vscp_writeEventToFrame(frame.data(), frame.size(), 0, pev)) {
                spdlog::error("TCP/IP binary: failed to serialize outgoing event");
                vscp_deleteEvent_v2(&pev);
                conn->is_closing = 1;
                return false;
            }
            sent = writeBinaryFrame(conn, std::move(frame));
        }
        else {
            vscp_convertEventToString(strOut, pev);
            strOut += ("\r\n");
            sent = write(conn, strOut.data(), strOut.size());
        }
        vscp_deleteEvent_v2(&pev);
        if (!sent) {
            spdlog::error("sendOneEventFromQueue: failed to send event");
            return false;
        }
    }
    else {
        if (bStatusMsg) {
            write(conn, MSG_NO_MSG, strlen(MSG_NO_MSG));
        }

        return false;
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// handleClientDataAvailable
//

void
CTcpipSrv::handleClientDataAvailable(struct mg_connection* conn)
{
    char outbuf[1024];

    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Get user item (can be NULL if not logged in)
    auto pUserItem = pClientItem->getUserItem();

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error(
          "Client is not connected, cannot handle client data available.");
        return;
    }

    // Must be accredited to do this
    if ((nullptr == pUserItem) || !pClientItem->isAuthenticated()) {
        spdlog::debug(
          "handleClientDataAvailable: Client is not authenticated.");
        write(conn, MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
        return;
    }

    // Get number of available events from the send queue
    size_t nAvailable = pClientItem->getSendQueueSize();
    sprintf(outbuf, "%zd\r\n%s", nAvailable, MSG_OK);

    write(conn, outbuf, strlen(outbuf));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientClearInputQueue
//

void
CTcpipSrv::handleClientClearInputQueue(struct mg_connection* conn)
{
    // Must be connected
    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Get user item (can be NULL if not logged in)
    auto pUserItem = pClientItem->getUserItem();

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error(
          "Client is not connected, cannot handle client clear input queue.");
        return;
    }

    // Must be accredited to do this
    if (!pClientItem->isAuthenticated()) {
        spdlog::debug(
          "handleClientClearInputQueue: Client is not authenticated.");
        write(conn, MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
        return;
    }

    pClientItem->clearSendQueue();

    write(conn, MSG_QUEUE_CLEARED, strlen(MSG_QUEUE_CLEARED));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientGetStatistics
//

void
CTcpipSrv::handleClientGetStatistics(struct mg_connection* conn)
{
    char outbuf[1024];

    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Get user item (can be NULL if not logged in)
    auto pUserItem = pClientItem->getUserItem();

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error(
          "Client is not connected, cannot handle client get statistics.");
        return;
    }

    // Must be accredited to do this
    if ((nullptr == pUserItem) || !pClientItem->isAuthenticated()) {
        spdlog::debug(
          "handleClientGetStatistics: Client is not authenticated.");
        write(conn, MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
        return;
    }

    sprintf(outbuf,
            "%lu,%lu,%lu,%lu,%lu,%lu,%lu\r\n%s",
            pClientItem->getStatistics().cntBusOff,
            pClientItem->getStatistics().cntBusWarnings,
            pClientItem->getStatistics().cntOverruns,
            pClientItem->getStatistics().cntReceiveData,
            pClientItem->getStatistics().cntReceiveFrames,
            pClientItem->getStatistics().cntTransmitData,
            pClientItem->getStatistics().cntTransmitFrames,
            MSG_OK);

    write(conn, outbuf, strlen(outbuf));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientGetStatus
//

void
CTcpipSrv::handleClientGetStatus(struct mg_connection* conn)
{
    char outbuf[1024];

    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Get user item (can be NULL if not logged in)
    auto pUserItem = pClientItem->getUserItem();

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error(
          "Client is not connected, cannot handle client get status.");
        return;
    }

    // Must be accredited to do this
    if ((nullptr == pUserItem) || !pClientItem->isAuthenticated()) {
        spdlog::debug("handleClientGetStatus: Client is not authenticated.");
        write(conn, MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
        return;
    }

    sprintf(outbuf,
            "%lu,%lu,%lu,\"%s\"\r\n%s",
            pClientItem->getStatus().channel_status,
            pClientItem->getStatus().lasterrorcode,
            pClientItem->getStatus().lasterrorsubcode,
            pClientItem->getStatus().lasterrorstr,
            MSG_OK);

    write(conn, outbuf, strlen(outbuf));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientGetChannelID
//

void
CTcpipSrv::handleClientGetChannelID(struct mg_connection* conn)
{
    char outbuf[1024];

    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Get user item (can be NULL if not logged in)
    auto pUserItem = pClientItem->getUserItem();

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error(
          "Client is not connected, cannot handle client get channel ID.");
        return;
    }

    // Must be accredited to do this
    if ((nullptr == pUserItem) || !pClientItem->isAuthenticated()) {
        spdlog::debug("handleClientGetChannelID: Client is not authenticated.");
        write(conn, MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
        return;
    }

    // Cast client ID to unsigned long for consistency

    sprintf(outbuf,
            "%lu\r\n%s",
            (unsigned long)pClientItem->getClientID(),
            MSG_OK);

    write(conn, outbuf, strlen(outbuf));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientSetChannelGUID
//

void
CTcpipSrv::handleClientSetChannelGUID(struct mg_connection* conn)
{
    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Get user item (can be NULL if not logged in)
    auto pUserItem = pClientItem->getUserItem();

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error(
          "Client is not connected, cannot handle client set channel GUID.");
        return;
    }

    // Must be accredited to do this
    if ((nullptr == pUserItem) || !pClientItem->isAuthenticated()) {
        spdlog::error(
          "handleClientSetChannelGUID: Client is not authenticated.");
        write(conn, MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
        return;
    }

    vscp_trim(getCurrentCommand());

    pClientItem->getInterfaceGUID().getFromString(getCurrentCommand());
    write(conn, MSG_OK, strlen(MSG_OK));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientGetChannelGUID
//

void
CTcpipSrv::handleClientGetChannelGUID(struct mg_connection* conn)
{
    std::string strBuf;

    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Get user item (can be NULL if not logged in)
    auto pUserItem = pClientItem->getUserItem();

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error(
          "Client is not connected, cannot handle client get channel GUID.");
        return;
    }

    // Must be accredited to do this
    if ((nullptr == pUserItem) || !pClientItem->isAuthenticated()) {
        spdlog::error(
          "handleClientGetChannelGUID: Client is not authenticated.");
        write(conn, MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
        return;
    }

    pClientItem->getInterfaceGUID().toString(strBuf);
    strBuf += std::string("\r\n");
    strBuf += std::string(MSG_OK);

    write(conn, strBuf);
}

///////////////////////////////////////////////////////////////////////////////
// handleClientGetVersion
//

void
CTcpipSrv::handleClientGetVersion(struct mg_connection* conn)
{
    char outbuf[1024];

    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error(
          "Client is not connected, cannot handle client get version.");
        return;
    }

    sprintf(outbuf,
            "%d,%d,%d\r\n%s",
            VSCPD_VERSION_MAJOR,
            VSCPD_VERSION_MINOR,
            VSCPD_VERSION_PATCH,
            MSG_OK);

    write(conn, outbuf, strlen(outbuf));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientSetFilter
//

void
CTcpipSrv::handleClientSetFilter(struct mg_connection* conn)
{
    // Must be connected
    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Get user item (can be NULL if not logged in)
    auto pUserItem = pClientItem->getUserItem();

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error(
          "Client is not connected, cannot handle client set filter.");
        return;
    }

    // Must be accredited to do this
    if ((nullptr == pUserItem) || !pClientItem->isAuthenticated()) {
        spdlog::error("handleClientSetFilter: Client is not authenticated.");
        write(conn, MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
        return;
    }
    vscp_trim(getCurrentCommand());

    std::string str;
    vscp_trim(getCurrentCommand());
    std::deque<std::string> tokens;
    vscp_split(tokens, getCurrentCommand(), ",");

    // Get priority
    if (!tokens.empty()) {
        str = tokens.front();
        tokens.pop_front();
        pClientItem->getFilter().filter_priority = vscp_readStringValue(str);
    }
    else {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    // Get Class
    if (!tokens.empty()) {
        str = tokens.front();
        tokens.pop_front();
        pClientItem->getFilter().filter_class = vscp_readStringValue(str);
    }
    else {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    // Get Type
    if (!tokens.empty()) {
        str = tokens.front();
        tokens.pop_front();
        pClientItem->getFilter().filter_type = vscp_readStringValue(str);
    }
    else {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    // Get GUID
    if (!tokens.empty()) {
        str = tokens.front();
        tokens.pop_front();
        vscp_getGuidFromStringToArray(pClientItem->getFilter().filter_GUID,
                                      str);
    }
    else {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    write(conn, MSG_OK, strlen(MSG_OK));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientSetMask
//

void
CTcpipSrv::handleClientSetMask(struct mg_connection* conn)
{
    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Get user item (can be NULL if not logged in)
    auto pUserItem = pClientItem->getUserItem();

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error(
          "Client is not connected, cannot handle client set mask.");
        return;
    }

    // Must be accredited to do this
    if ((nullptr == pUserItem) || !pClientItem->isAuthenticated()) {
        spdlog::error("handleClientSetMask: Client is not authenticated.");
        write(conn, MSG_NOT_ACCREDITED, strlen(MSG_NOT_ACCREDITED));
        return;
    }

    std::string str;
    vscp_trim(getCurrentCommand());
    std::deque<std::string> tokens;
    vscp_split(tokens, getCurrentCommand(), ",");

    // Get priority
    if (!tokens.empty()) {
        str = tokens.front();
        tokens.pop_front();
        pClientItem->getFilter().mask_priority = vscp_readStringValue(str);
    }
    else {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    // Get Class
    if (!tokens.empty()) {
        str = tokens.front();
        tokens.pop_front();
        pClientItem->getFilter().mask_class = vscp_readStringValue(str);
    }
    else {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    // Get Type
    if (!tokens.empty()) {
        str = tokens.front();
        tokens.pop_front();
        pClientItem->getFilter().mask_type = vscp_readStringValue(str);
    }
    else {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    // Get GUID
    if (!tokens.empty()) {
        str = tokens.front();
        tokens.pop_front();
        vscp_getGuidFromStringToArray(pClientItem->getFilter().mask_GUID, str);
    }
    else {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    write(conn, MSG_OK, strlen(MSG_OK));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientUser
//

void
CTcpipSrv::handleClientUser(struct mg_connection* conn)
{
    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error("Client is not connected, cannot handle client user.");
        return;
    }

    // If authenticatd user is already set, just return OK.
    if ((nullptr != pClientItem->getUserItem()) &&
        pClientItem->isAuthenticated()) {
        spdlog::info("User is already authenticated.");
        write(conn, MSG_OK, strlen(MSG_OK));
        return;
    }

    auto pUserItem =
      m_pCtrlObj->getUserList().getUser(getCurrentCommand().c_str());
    if (nullptr == pUserItem) {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }
    pClientItem->setUserItem(pUserItem);

    write(conn, MSG_USERNAME_OK, strlen(MSG_USERNAME_OK));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientPassword
//

bool
CTcpipSrv::handleClientPassword(struct mg_connection* conn)
{
    // Check pointer
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return false;
    }

    // Must have a client item associated with the connection
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has no associated client item.");
        return false;
    }

    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Get user item (can be nullptr if not logged in)
    auto pUserItem = pClientItem->getUserItem();
    if (nullptr == pUserItem) {
        spdlog::info("Must enter username before password.");
        write(conn, MSG_NEED_USERNAME, strlen(MSG_NEED_USERNAME));
        return false;
    }

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error(
          "Client is not connected, cannot handle client password.");
        return false;
    }

    /*!
        When a user name is entered a useritem is set, fetched from
        one of the users in the userlist that is filled from the
        configuration file on startup.
    */

    // Must must have a username before password can be entered.
    if ((nullptr != pUserItem) && (0 == pUserItem->getUserName().length())) {
        write(conn, MSG_INVALID_USER, strlen(MSG_INVALID_USER));
        return false;
    }

    std::string strPassword = getCurrentCommand();
    vscp_trim(strPassword);

    // Must be a password
    if (strPassword.empty()) {
        pClientItem->setUserItem(nullptr);
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return false;
    }

    if (!pUserItem->validatePassword(strPassword)) {

        std::string strErr = vscp_str_format(
          ("[TCP/IP srv] User [%s] not allowed to connect.\n"),
          (const char*)pUserItem->getUserName().c_str());

        spdlog::error("%s", strErr.c_str());
        write(conn, MSG_PASSWORD_ERROR, strlen(MSG_PASSWORD_ERROR));

        // Remove the user
        pClientItem->setUserItem(nullptr);
        spdlog::info("User removed due to failed password validation.");

        return false;
    }

    // Get remote address
    struct sockaddr_in cli_addr;
    socklen_t clilen = 0;
    clilen           = sizeof(cli_addr);
    (void)getpeername((int)(uintptr_t)conn->fd,
                      (struct sockaddr*)&cli_addr,
                      &clilen);
    std::string remoteaddr = std::string(inet_ntoa(cli_addr.sin_addr));

    // Check if this user is allowed to connect from this location
    // pthread_mutex_lock(&m_pCtrlObj->m_mutex_UserList);
    bool bValidHost =
      (1 == pUserItem->isAllowedToConnect(cli_addr.sin_addr.s_addr));
    // pthread_mutex_unlock(&m_pCtrlObj->m_mutex_UserList);

    if (!bValidHost) {
        std::string strErr =
          vscp_str_format(("[TCP/IP srv] Host [%s] not allowed to connect.\n"),
                          (const char*)remoteaddr.c_str());

        spdlog::error("%s", strErr.c_str());
        write(conn, MSG_INVALID_REMOTE_ERROR, strlen(MSG_INVALID_REMOTE_ERROR));
        return false;
    }

    // Copy in the user filter
    memcpy(&pClientItem->getFilter(),
           pUserItem->getUserFilter(),
           sizeof(vscpEventFilter));

    std::string strErr = vscp_str_format(
      ("[TCP/IP srv] Host [%s] User [%s] allowed to connect.\n"),
      (const char*)remoteaddr.c_str(),
      (const char*)pUserItem->getUserName().c_str());

    spdlog::info("{}", strErr.c_str());

    pClientItem->setAuthenticated(true);

    // pClientItem->setUserItem(nullptr);
    write(conn, MSG_OK, strlen(MSG_OK));

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// handleChallenge
//

void
CTcpipSrv::handleChallenge(struct mg_connection* conn)
{
    std::string str;

    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error("Client is not connected, cannot handle challenge.");
        return;
    }

    char sid[32] = { 0 };
    char buf[65] = { 0 };
    mg_random(sid, sizeof(sid));
    for (size_t i = 0; i < sizeof(sid); i++) {
        mg_snprintf(buf + i * 2, 3, "%02x", sid[i]);
    }
    pClientItem->setSessionId(buf);

    str = std::string("+OK - ") + buf + std::string("\r\n");
    write(conn, str);
}

///////////////////////////////////////////////////////////////////////////////
// handleClientRcvLoop
//

void
CTcpipSrv::handleClientRcvLoop(struct mg_connection* conn)
{
    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error("Client is not connected, cannot enter receive loop.");
        return;
    }

    // Mark client item as being in receive loop
    pClientItem->setReceiveLoop(true);

    // Notify the client that it has entered the receive loop
    write(conn, MSG_RECEIVE_LOOP, strlen(MSG_RECEIVE_LOOP));

    // Clear the read buffer before entering the receive loop
    // pClientItem->clearReadBuffer();

    return;
}

///////////////////////////////////////////////////////////////////////////////
// handleClientQuitRcvLoop
//

void
CTcpipSrv::handleClientQuitRcvLoop(struct mg_connection* conn)
{
    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error("Client is not connected, cannot enter receive loop.");
        return;
    }

    // Mark client item as having quit the receive loop
    pClientItem->setReceiveLoop(false);

    // Notify the client that it has quit the receive loop
    write(conn, MSG_QUIT_LOOP, strlen(MSG_QUIT_LOOP));

    return;
}

///////////////////////////////////////////////////////////////////////////////
// handleClientTest
//

void
CTcpipSrv::handleClientTest(struct mg_connection* conn)
{
    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    write(conn, MSG_OK, strlen(MSG_OK));
    return;
}

///////////////////////////////////////////////////////////////////////////////
// handleClientRestart
//

void
CTcpipSrv::handleClientRestart(struct mg_connection* conn)
{
    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    write(conn, MSG_OK, strlen(MSG_OK));

    sleep(1);
#ifdef WIN32
    if (m_pCtrlObj) {
        m_pCtrlObj->m_bQuit = true;
    }
#else
    kill(getpid(), SIGUSR2);
#endif

    return;
}

///////////////////////////////////////////////////////////////////////////////
// handleClientShutdown
//

void
CTcpipSrv::handleClientShutdown(struct mg_connection* conn)
{
    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Get user item (can be NULL if not logged in)
    auto pUserItem = pClientItem->getUserItem();

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error("Client is not connected, cannot handle shutdown.");
        return;
    }

    spdlog::info("tcp/ip client requested shutdown!!!");

    if ((nullptr == pUserItem) || !pClientItem->isAuthenticated()) {
        write(conn, MSG_OK, strlen(MSG_OK));
    }

    write(conn, MSG_GOODBY, strlen(MSG_GOODBY));
    sleep(1);

#ifdef WIN32
    if (m_pCtrlObj) {
        m_pCtrlObj->m_bQuit = true;
    }
#else
    kill(getpid(), SIGUSR1);
#endif
}

///////////////////////////////////////////////////////////////////////////////
// handleClientRemote
//

void
CTcpipSrv::handleClientRemote(struct mg_connection* conn)
{
    return;
}

// -----------------------------------------------------------------------------
//                            I N T E R F A C E
// -----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// handleClientInterface
//
// list     List interfaces.
// unique   Acquire selected interface uniquely. Full format is INTERFACE UNIQUE
// id normal   Normal access to interfaces. Full format is INTERFACE NORMAL id
// close    Close interfaces. Full format is INTERFACE CLOSE id

void
CTcpipSrv::handleClientInterface(struct mg_connection* conn)
{
    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error(
          "Client is not connected, cannot handle interface command.");
        return;
    }

    if (commandStartsWith(("list"))) {
        handleClientInterface_List(conn);
    }
    else if (commandStartsWith(("unique"))) {
        handleClientInterface_Unique(conn);
    }
    else if (commandStartsWith(("normal"))) {
        handleClientInterface_Normal(conn);
    }
    else if (commandStartsWith(("close"))) {
        handleClientInterface_Close(conn);
    }
    else {
        handleClientInterface_List(conn);
    }
}

///////////////////////////////////////////////////////////////////////////////
// handleClientInterface_List
//

void
CTcpipSrv::handleClientInterface_List(struct mg_connection* conn)
{
    std::string strGUID;
    std::string strBuf;

    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Display Interface List
    m_pCtrlObj->getClientList().lockClientItemList();

    std::deque<CClientItem*>::iterator it;
    for (it = m_pCtrlObj->getClientList().getItemList().begin();
         it != m_pCtrlObj->getClientList().getItemList().end();
         ++it) {

        CClientItem* pItem = *it;
        pItem->getInterfaceGUID().toString(strGUID);
        strBuf = vscp_str_format("%d,", pItem->getClientID());
        strBuf += vscp_str_format("%d,", pItem->getInterfaceType());
        strBuf += strGUID;
        strBuf += std::string(",");
        strBuf += pItem->getDeviceName().c_str();
        strBuf += std::string(" | Started at ");
        strBuf += pItem->getDateTimeStarted().getISODateTime();
        strBuf += std::string("\r\n");

        write(conn, strBuf);
    }

    write(conn, MSG_OK, strlen(MSG_OK));

    m_pCtrlObj->getClientList().unlockClientItemList();
}

///////////////////////////////////////////////////////////////////////////////
// handleClientInterface_Unique
//

void
CTcpipSrv::handleClientInterface_Unique(struct mg_connection* conn)
{
    unsigned char ifGUID[16];
    memset(ifGUID, 0, 16);

    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error(
          "Client is not connected, cannot handle interface unique command.");
        return;
    }

    // Get GUID
    vscp_trim(getCurrentCommand());
    vscp_getGuidFromStringToArray(ifGUID, getCurrentCommand());

    // Add the client to the Client List
    // TODO

    write(conn, MSG_INTERFACE_NOT_FOUND, strlen(MSG_INTERFACE_NOT_FOUND));
}

///////////////////////////////////////////////////////////////////////////////
// handleClientInterface_Normal
//

void
CTcpipSrv::handleClientInterface_Normal(struct mg_connection* conn)
{
    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // TODO
}

///////////////////////////////////////////////////////////////////////////////
// handleClientInterface_Close
//

void
CTcpipSrv::handleClientInterface_Close(struct mg_connection* conn)
{
    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has noassociated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // TODO
}

// -----------------------------------------------------------------------------
//                          E N D   I N T E R F A C E
// -----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// handleClientHelp
//

void
CTcpipSrv::handleClientHelp(struct mg_connection* conn)
{
    // Check that conn is valid
    if (nullptr == conn) {
        spdlog::info("Connection is NULL.");
        return;
    }

    // Client item must be available
    if (nullptr == conn->fn_data) {
        spdlog::info("Connection has no associated client item.");
        return;
    }

    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

    // Must be connected
    if (!pClientItem->isConnected()) {
        spdlog::error("Client is not connected, cannot handle help command.");
        return;
    }

    if (0 == getCurrentCommand().length()) {

        std::string str = "\r\nHelp for the VSCP tcp/ip interface\r\n";
        str += "=============================================================="
               "======\r\n";
        str += "To get more information about a specific command issue 'HELP "
               "command or read here "
               "https://grodansparadis.github.io/vscp-doc-spec/#/./"
               "vscp_tcpiplink'\r\n";
        str += "+                 - Repeat last command.\r\n";
        str += "+n                - Repeat command 'n' (0 is last).\r\n";
        str += "++                - List repeatable commands.\r\n";
        str += "NOOP              - No operation. Does nothing.\r\n";
        str += "QUIT              - Close the connection.\r\n";
        str += "USER 'username'   - Username for login. \r\n";
        str += "PASS 'password'   - Password for login.  \r\n";
        str += "CHALLENGE 'token' - Get session id.  \r\n";
        str += "SEND 'event'      - Send an event.   \r\n";
        str += "RETR 'count'      - Retrive n events from input queue.   \r\n";
        str +=
          "RCVLOOP           - Will retrieve events in an endless loop until "
          "the connection is closed by the client or QUITLOOP is sent.\r\n";
        str += "QUITLOOP          - Terminate RCVLOOP.\r\n";
        str += "CDTA/CHKDATA      - Check if there is data in the input "
               "queue.\r\n";
        str += "CLRA/CLRALL       - Clear input queue.\r\n";
        str += "STAT              - Get statistical information.\r\n";
        str += "INFO              - Get status info.\r\n";
        str += "CHID              - Get channel id.\r\n";
        str += "SGID/SETGUID      - Set GUID for channel.\r\n";
        str += "GGID/GETGUID      - Get GUID for channel.\r\n";
        str += "VERS/VERSION      - Get VSCP daemon version.\r\n";
        str += "SFLT/SETFILTER    - Set incoming event filter.\r\n";
        str += "SMSK/SETMASK      - Set incoming event mask.\r\n";
        str += "HELP [command]    - This command.\r\n";
        str += "TEST              - Do test sequence. Only used for "
               "debugging.\r\n";
        str += "SHUTDOWN          - Shutdown the daemon.\r\n";
        str += "RESTART           - Restart the daemon.\r\n";
        str += "INTERFACE         - Interface handling. \r\n";
        str += "WCYD/WHATCANYOUDO - Check server capabilities. \r\n";
        str += "MEASUREMENT       - Post measurement event. \r\n";
        str += "BINARY            - Enter binary mode. \r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("+")) {
        std::string str = "'+' repeats the last given command.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("noop", true)) {
        std::string str =
          "'NOOP' Does absolutely nothing but giving a success in return.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("quit", true)) {
        std::string str = "'QUIT' Quit a session with the VSCP daemon and "
                          "closes the m_connection.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("user", true)) {
        std::string str =
          "'USER' Used to login to the system together with PASS. Connection "
          "will be closed if bad credentials are given.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("pass", true)) {
        std::string str =
          "'PASS' Used to login to the system together with USER. Connection "
          "will be closed if bad credentials are given.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("quit", true)) {
        std::string str = "'QUIT' Quit a session with the VSCP daemon and "
                          "closes the m_connection.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("send", true)) {
        std::string str = "'SEND event'.\r\nThe event is given as "
                          "'head,class,type,obid,datetime,time-stamp,GUID,"
                          "data1,data2,data3....' \r\n";
        str +=
          "Normally set 'head' and 'obid' to zero. \r\nIf timestamp is set to "
          "zero it will be set by the server. \r\nIf GUID is given as '-' ";
        str += "the GUID of the interface will be used. \r\nThe GUID should "
               "be given on the form MSB-byte:MSB-byte-1:MSB-byte-2. \r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("retr", true)) {
        std::string str = "'RETR count' - Retrieve one (if no argument) or "
                          "'count' event(s). ";
        str += "Events are retrived on the form "
               "head,class,type,obid,,ns-time-stamp,GUID,data0,data1,"
               "data2,...........\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("rcvloop", true)) {
        std::string str = "'RCVLOOP' - Enter the receive loop and receive "
                          "events continously or until ";
        str +=
          "terminated with 'QUITLOOP'. Events are retrived on the form "
          "head,class,type,obid,,ns-time-stamp,GUID,data0,data1,data2,......."
          "....\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("quitloop", true)) {
        std::string str = "'QUITLOOP' - End 'RCVLOOP' event receives.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("cdta", true) ||
             commandStartsWith("chkdata", true)) {
        std::string str = "'CDTA' or 'CHKDATA' - Check if there is events in "
                          "the input queue.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("clra", true) ||
             commandStartsWith("clrall", true)) {
        std::string str = "'CLRA' or 'CLRALL' - Clear input queue.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("stat", true)) {
        std::string str = "'STAT' - Get statistical information.\r\n";
        str += "Format is "
               "x,y,z,cntReceiveData,cntReceiveFrames,cntTransmitData,"
               "cntTransmitFrames\r\n";
        str += "x = always zero, y = always zero, z = always zero\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("info", true)) {
        std::string str = "'INFO' - Get status information.\r\n";
        str +=
          "channel-status,lasterrorcode,lasterrorsubcode,\"lasterrorstr\"\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("chid", true) ||
             commandStartsWith("getchid", true)) {
        std::string str = "'CHID' or 'GETCHID' - Get channel id.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("sgid", true) ||
             commandStartsWith("setguid", true)) {
        std::string str = "'SGID' or 'SETGUID' - Set GUID for channel.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("ggid", true) ||
             commandStartsWith("getguid", true)) {
        std::string str = ("'GGID' or 'GETGUID' - Get GUID for channel.\r\n");
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("vers", true) ||
             commandStartsWith("version", true)) {
        std::string str =
          "'VERS' or 'VERSION' - Get version of VSCP daemon.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("sflt", true) ||
             commandStartsWith("setfilter", true)) {
        std::string str = "'SFLT' or 'SETFILTER' - Set filter for channel. ";
        str += "The format is 'filter-priority, filter-class, filter-type, "
               "filter-GUID' \r\n";
        str += "Example:  \r\nSETFILTER "
               "1,0x0000,0x0006,ff:ff:ff:ff:ff:ff:ff:01:00:00:00:00:00:00:00:"
               "00\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("smsk", true) ||
             commandStartsWith("setmask", true)) {
        std::string str = "'SMSK' or 'SETMASK' - Set mask for channel. ";
        str += "The format is 'mask-priority, mask-class, mask-type, "
               "mask-GUID' \r\n";
        str += "Example:  \r\nSETMASK "
               "0x0f,0xffff,0x00ff,ff:ff:ff:ff:ff:ff:ff:01:00:00:00:00:00:00:"
               "00:00 \r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("help", true)) {
        std::string str = "'HELP [command]' This command. Gives help about "
                          "available commands and the usage.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("test", true)) {
        std::string str = "'TEST [sequency]' Test command for debugging.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("shutdown", true)) {
        std::string str = "'SHUTDOWN' Shutdown the daemon.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("restart", true)) {
        std::string str = "'RESTART' Restart the daemon.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("interface", true)) {
        std::string str =
          "'INTERFACE' list interfaces on the daemon. Format is\r\n";
        str += "'count'.\r\n";
        str +=
          "'Row(s) with interface details: (clientid, type, guid,name)'.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("wcyd", true) ||
             commandStartsWith("whatcanyoudo", true)) {
        std::string str = "'WCYD/WHATCANYOUDO' Return the VSCP server "
                          "capabilities as a 64-bit array.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("measurement", true)) {
        std::string str = "'MEASUREMENT' Post measurement event.\r\n";
        str +=
          "Syntax: measurement class,type,value,[unit],[index],[guid].\r\n";
        str += "Example: measurement "
               "10,6,23.5,1,0,00:00:00:00:00:00:00:00:00:00:00:00\r\n";
        str +=
          "Default unit=0, Default index=0. Default GUID=interface GUID.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("binary", true)) {
        std::string str = "'BINARY' Enter binary mode.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else {
        std::string str =
          vscp_str_format("The command '%s' is not available\r\n",
                          getCurrentCommand().c_str());
        write(conn, (const char*)str.c_str(), str.length());
    }

    write(conn, MSG_OK, strlen(MSG_OK));
    return;
}

///////////////////////////////////////////////////////////////////////////////
// tcpip_event_handler
//
// Handle TCP/IP events for the server
//

static void
tcpip_event_handler(struct mg_connection* conn, int ev, void* ev_data)
{
    auto* server = static_cast<CTcpipSrv*>(conn->mgr->userdata);
    if (server == nullptr) {
        spdlog::error("TCP/IP event handler: missing server");
        return;
    }

    CControlObject* pobj = server->getControlObject();
    if (pobj == nullptr) {
        spdlog::error("TCP/IP event handler: missing control object");
        return;
    }

    // // Get the TCP/IP server object from the thread data.
    // CControlObject* pobj = pClientItem->getControlObject();
    // if (nullptr == pobj) {
    //     spdlog::error("[TCP/IP srv client thread] Error, "
    //                   "Client thread control object not initialized.");
    //     return;
    // }

    // Handle communication events
    if (ev == MG_EV_OPEN && conn->is_listening == 1) {
        spdlog::debug("SERVER is listening");
    }
    else if (ev == MG_EV_ACCEPT) {

#ifdef WITH_WRAP
        /* Use tcpd / libwrap to determine whether a connection
         * is allowed. */
        request_init(&wrap_req, RQ_FILE, conn->fd, RQ_DAEMON, "vscpd", 0);
        fromhost(&wrap_req);
        if (!hosts_access(&wrap_req)) {
            // Access is denied
            if (!stcp_socket_get_address(conn, address, 1024)) {
                spdlog::error("Client connection from %s "
                              "denied access by tcpd.",
                              address);
            }
            // Close the connection
            conn->is_closing = 1;
            continue;
        }
#endif

        spdlog::debug("SERVER accepted a connection");
        if (mg_url_is_ssl(pobj->getTcpipSrv().getInterfaceAddress().c_str())) {
            spdlog::debug("SERVER accepted a secure (SSL/TLS) connection");
            struct mg_tls_opts opts = pobj->getTcpipSrv().getTlsOpts();
            mg_tls_init(conn, &opts);
        }

        // Create a new client item for this connection
        CClientItem* newClient =
          new CClientItem(pobj,
                          CClientItem::CLIENT_ITEM_INTERFACE_TYPE::
                            CLIENT_ITEM_INTERFACE_TYPE_CLIENT_TCPIP,
                          conn);

        // Add to client list
        if (!pobj->addClient(newClient)) {
            mg_send(conn, MSG_INTERNAL_ERROR, strlen(MSG_INTERNAL_ERROR));
            spdlog::error("Failed to add new client to the server");
            delete newClient;
            conn->is_closing = 1;
            return;
        }

        // Set unique GUID for the client based on the control object's GUID
        cguid guid = pobj->getGUID();
        guid.setClientID(newClient->getClientID());
        newClient->setInterfaceGUID(guid);

        // Associate the new client item with the connection
        conn->fn_data = newClient;

        std::string deviceName = "TCP/IP Client. clientid = " +
                                 std::to_string(newClient->getClientID());
        newClient->setDeviceName(deviceName);

        // Mark as connected
        newClient->setConnected(true);

        // Mark as open
        newClient->setOpen(true);

        // Remote address as tracked by mongoose (portable, no raw socket calls)
        char remote_address[64] = "";
        mg_snprintf(remote_address,
                    sizeof(remote_address),
                    "%M",
                    mg_print_ip,
                    &conn->rem);
        unsigned int port = mg_ntohs(conn->rem.port);

        spdlog::info("New TCP/IP client connected with clientid = {} remote "
                     "address = {} port = {}",
                     newClient->getClientID(),
                     remote_address,
                     port);

        // Greet the new client (without the string terminators)
        mg_send(conn, MSG_WELCOME, sizeof(MSG_WELCOME) - 1);
        mg_send(conn, VSCPD_DISPLAY_VERSION, sizeof(VSCPD_DISPLAY_VERSION) - 1);
        mg_send(conn, "\r\n", 2);
        mg_send(conn, VSCPD_COPYRIGHT, sizeof(VSCPD_COPYRIGHT) - 1);
        mg_send(conn, "\r\n", 2);
        mg_send(conn, MSG_OK, sizeof(MSG_OK) - 1);
        spdlog::debug("SERVER sent welcome message");
    }

    else if (ev == MG_EV_READ) {
        server->handleIncomingData(conn);
    }
    else if (ev == MG_EV_WAKEUP || ev == MG_EV_POLL) {
        if (ev == MG_EV_WAKEUP && conn->is_listening &&
            !conn->is_closing) {
            processMainReceiveQueue(server);
            return;
        }

        auto* pClientItem = static_cast<CClientItem*>(conn->fn_data);
        if (ev == MG_EV_POLL && !conn->is_listening && nullptr != pClientItem) {
            server->checkBinaryReceiveTimeout(conn, mg_millis());
        }
        if (conn->is_listening || conn->is_closing ||
            nullptr == pClientItem || !pClientItem->isConnected() ||
            !pClientItem->isReceiveLoopActive()) {
            return;
        }

        // Polling also delivers queued events if a wakeup was lost or failed.
        while (server->sendOneEventFromQueue(conn, false)) {
        }
    }
    else if (ev == MG_EV_CLOSE) {

        // Get client item
        CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);

        // Mark as disconnected
        if (nullptr != pClientItem) {
            pobj->getClientList().removeClient((CClientItem*)pClientItem);
        }
        conn->is_closing = 1; // Ensure the connection is marked as closing
        conn->fn_data    = nullptr; // Clear the client item from the connection

        spdlog::debug("SERVER disconnected (MG_EV_CLOSE)");
    }
    else if (ev == MG_EV_ERROR) {
        spdlog::error("SERVER error: {}", (char*)ev_data);
    }
}

///////////////////////////////////////////////////////////////////////////////
// tcpipWorkerThread
//
// This worker thread handles the communication with a single under single
// clients. Typically when events should be sent to all clients, this worker
// thread will handle the distribution of those events.
//

void*
tcpipWorkerThread(void* pdata)
{
    CTcpipSrv* ptcpipsrv = (CTcpipSrv*)pdata;
    if (nullptr == ptcpipsrv) {
        spdlog::error("[TCP/IP srv client thread] Error, "
                      "Client thread TCP/IP server object not initialized.");
        return nullptr;
    }

    // Get the TCP/IP server object from the thread data.
    CControlObject* pobj = ptcpipsrv->getControlObject();
    if (nullptr == pobj) {
        spdlog::error("[TCP/IP srv client thread] Error, "
                      "Client thread control object not initialized.");
        return nullptr;
    }

    //-------------------------------------------------------------------------
    //                            Initiate Mongoose
    //-------------------------------------------------------------------------
    // struct mg_mgr mgr; // Event manager
    struct mg_connection* conn;

    mg_log_set(MG_LL_INFO);         // Set log level
    crcInit();
    mg_mgr_init(&ptcpipsrv->m_mgr); // Initialize event manager
    ptcpipsrv->m_mgr.userdata = pdata;

    // Initialize the wakeup mechanism for the Mongoose event manager. This
    // allows other threads to wake up the event loop when needed.
    if (!mg_wakeup_init(&ptcpipsrv->m_mgr)) {
        spdlog::error("TCP/IP server: failed to initialize wakeup mechanism");
        mg_mgr_free(&ptcpipsrv->m_mgr);
        return nullptr;
    }

    // // Add a timer to the Mongoose event manager
    mg_timer_add(&ptcpipsrv->m_mgr,
                 100, // Every 100 milliseconds
                 MG_TIMER_REPEAT | MG_TIMER_RUN_NOW,
                 timer_fn,
                 &ptcpipsrv->m_mgr);

    // Start to listen for connections
    spdlog::debug("Starting TCP/IP server on interface: {}",
                  ptcpipsrv->getInterfaceAddress().c_str());

    conn = mg_listen(&ptcpipsrv->m_mgr,
                     ptcpipsrv->getInterfaceAddress().c_str(),
                     tcpip_event_handler,
                     nullptr); // Create server connection
    if (conn == NULL) {
        MG_INFO(("SERVER cant' open a connection"));
        mg_mgr_free(&ptcpipsrv->m_mgr);
        return nullptr;
    }

    pobj->getClientList().setMainReceiveQueueNotifier(
      [ptcpipsrv, connectionId = conn->id]() {
          if (!mg_wakeup(&ptcpipsrv->m_mgr, connectionId, "x", 1)) {
              spdlog::error("TCP/IP server: failed to wake main receive queue");
          }
      });
    processMainReceiveQueue(ptcpipsrv);

    // Event loop
    while (ptcpipsrv->isWorking()) {
        mg_mgr_poll(&ptcpipsrv->m_mgr, 1000); // Poll the event manager
    }

    // Clearing the notifier waits for in-flight notifications before freeing.
    pobj->getClientList().setMainReceiveQueueNotifier({});
    mg_mgr_free(&ptcpipsrv->m_mgr); // Free the event manager resources

    spdlog::debug("clientWorkerThread: Client worker thread exiting.");

    return nullptr; // Ensure the thread function returns a value even if it
                    // does nothing.
}

///////////////////////////////////////////////////////////////////////////////
// tcpipClientThread
//
// This thread handles a single TCP/IP client connection. It initializes the
// client structure, adds it to the client list, and manages communication with
// the client. It runs in its own thread and communicates with the client over
// the TCP/IP connection.
//

void*
tcpipClientThread(void* pData)
{
    // Get the TCP/IP server object from the thread data.
    CTcpipSrv* ptcpipsrv = (CTcpipSrv*)pData;
    if (NULL == ptcpipsrv) {
        spdlog::error("Client thread object not initialized.");
        return nullptr;
    }

    // Get the TCP/IP server object from the thread data.
    CControlObject* pobj = ptcpipsrv->getControlObject();
    if (nullptr == pobj) {
        spdlog::error("[TCP/IP srv client thread] Error, "
                      "Client thread control object not initialized.");
        return nullptr;
    }

    spdlog::debug("[TCP/IP srv client thread] Thread started.");

    // ptcpipsrv->pClientItem = new CClientItem();
    // if (NULL == ptcpipsrv->pClientItem) {
    //     spdlog::error("[TCP/IP srv client thread] Memory error, "
    //                   "Cant allocate client structure.");
    //     return nullptr;
    // }

    // vscpdatetime now;
    // ptcpipsrv->pClientItem->m_dtutc = now;
    // ptcpipsrv->pClientItem->m_bOpen = true;
    // ptcpipsrv->pClientItem->m_type  =
    // CLIENT_ITEM_INTERFACE_TYPE_CLIENT_TCPIP;
    // ptcpipsrv->pClientItem->m_strDeviceName =
    //   ("Remote tcp/ip server connection @ [");
    // ptcpipsrv->pClientItem->m_strDeviceName +=
    //   ptcpipsrv->m_pCtrlObj->m_interfaceAddress;
    // ptcpipsrv->pClientItem->m_strDeviceName += ("]");

    // // Start of activity
    // ptcpipsrv->pClientItem->m_clientActivity = time(NULL);

    // // Add the client to the Client List
    // pthread_mutex_lock(&ptcpipsrv->m_pCtrlObj->m_clientList.m_mutexClientItemList);
    // if (!ptcpipsrv->m_pCtrlObj->addClient(ptcpipsrv->pClientItem)) {
    //     // Failed to add client
    //     delete ptcpipsrv->pClientItem;
    //     ptcpipsrv->pClientItem = NULL;
    //     pthread_mutex_unlock(&ptcpipsrv->m_pCtrlObj->m_clientList.m_mutexClientItemList);
    //     spdlog::error(
    //       "TCP/IP server: Failed to add client. Terminating thread.");
    //     return nullptr;
    // }
    // pthread_mutex_unlock(&ptcpipsrv->m_pCtrlObj->m_clientList.m_mutexClientItemList);

    // // Clear the filter (Allow everything )
    // vscp_clearVSCPFilter(&ptcpipsrv->pClientItem->m_filter);

    // // Send welcome message
    // std::string str = std::string(MSG_WELCOME);
    // str += std::string("Version: ");
    // str += std::string(VSCPD_DISPLAY_VERSION);
    // str += std::string("\r\n");
    // str += std::string(VSCPD_COPYRIGHT);
    // str += std::string("\r\n");
    // str += std::string(MSG_OK);
    // ptcpipsrv->write(conn,(const char*)str.c_str(), str.length());

    // spdlog::debug("[TCP/IP srv] Ready to serve client.");

    // // Enter command loop
    // char buf[8192];
    // struct pollfd fd;
    // while (!ptcpipsrv->m_pParent->m_nStopTcpIpSrv) {

    //     // Check for client inactivity
    //     if ((time(nullptr) - ptcpipsrv->pClientItem->m_clientActivity) >
    //         TCPIPSRV_INACTIVITY_TIMOUT) {
    //         spdlog::info(
    //           "[TCP/IP srv client thread] Client closed due to inactivity.");
    //         break;
    //     }

    //     // * * * Receiveloop * * *
    //     if (ptcpipsrv->m_bReceiveLoop) {

    //         // Wait for data
    //         vscp_sem_wait(&ptcpipsrv->pClientItem->m_semClientInputQueue,
    //         10);

    //         // Send everything in the queue
    //         while (ptcpipsrv->sendOneEventFromQueue(false))
    //             ;

    //         // Send '+OK<CR><LF>' every two seconds to indicate that the
    //         // link is open
    //         if ((time(nullptr) - ptcpipsrv->pClientItem->m_timeRcvLoop) > 2)
    //         {
    //             ptcpipsrv->pClientItem->m_timeRcvLoop    = time(nullptr);
    //             ptcpipsrv->pClientItem->m_clientActivity = time(nullptr);
    //             ptcpipsrv->write(conn,"+OK\r\n", 5);
    //         }
    //     }
    //     else {

    //         // Set poll
    //         fd.fd      = ptcpipsrv->m_conn->client.sock;
    //         fd.events  = POLLIN;
    //         fd.revents = 0;

    //         // Wait for data
    //         if (stcp_poll(&fd,
    //                       1,
    //                       500,
    //                       &(ptcpipsrv->m_pParent->m_nStopTcpIpSrv)) < 0) {
    //             continue; // Nothing
    //         }

    //         // Data in?
    //         if (!(fd.revents & POLLIN)) {
    //             continue;
    //         }
    //     }

    //     // Read possible data from client
    //     //      If in receive loop we know we have delay
    //     //      in event waiting above.
    //     memset(buf, 0, sizeof(buf));
    //     int nRead = stcp_read(ptcpipsrv->m_conn,
    //                           buf,
    //                           sizeof(buf),
    //                           (ptcpipsrv->m_bReceiveLoop) ? 0 : 0);

    //     if (0 == nRead) {
    //         ; // Nothing more to read - Check for command and continue ->
    //         below
    //     }
    //     else if (nRead < 0) {

    //         if (STCP_ERROR_TIMEOUT == nRead) {
    //             ptcpipsrv->m_rv = VSCP_ERROR_TIMEOUT;
    //         }
    //         else if (STCP_ERROR_STOPPED == nRead) {
    //             ptcpipsrv->m_rv = VSCP_ERROR_STOPPED;
    //             continue;
    //         }
    //         break;
    //     }
    //     else if (nRead > 0) {
    //         ptcpipsrv->m_strResponse += std::string(buf, nRead);
    //     }

    //     // Record client activity
    //     ptcpipsrv->pClientItem->m_clientActivity = time(nullptr);

    //     // get data up to "\r\n" if any
    //     size_t pos;
    //     if (ptcpipsrv->m_strResponse.npos !=
    //         (pos = ptcpipsrv->m_strResponse.find("\n"))) {

    //         // Get the command
    //         std::string strCommand =
    //           vscp_str_left(ptcpipsrv->m_strResponse, pos + 1);

    //         // Save the unhandled part
    //         ptcpipsrv->m_strResponse =
    //           vscp_str_right(ptcpipsrv->m_strResponse,
    //                          ptcpipsrv->m_strResponse.length() - pos - 1);

    //         // Remove whitespace
    //         vscp_trim(strCommand);

    //         // If nothing to do do nothing - pretty obious if you think about
    //         it if (0 == strCommand.length())
    //             continue;

    //         // Check for repeat command
    //         // +    - repear last command
    //         // +n   - Repeat n-th command
    //         // ++
    //         if (ptcpipsrv->m_commandArray.size() && ('+' == strCommand[0])) {

    //             if (vscp_startsWith(strCommand, "++", &strCommand)) {
    //                 for (int i = ptcpipsrv->m_commandArray.size() - 1; i >=
    //                 0;
    //                      i--) {
    //                     std::string str = vscp_str_format(
    //                       "%d - %s",
    //                       ptcpipsrv->m_commandArray.size() - i - 1,
    //                       ptcpipsrv->m_commandArray[i].c_str());
    //                     vscp_trim(str);
    //                     ptcpipsrv->write(conn,str, true);
    //                 }
    //                 continue;
    //             }

    //             // Get pos
    //             unsigned int n = 0;
    //             if (strCommand.length() > 1) {
    //                 strCommand = strCommand.substr(strCommand.length() - 1);
    //                 n          = vscp_readStringValue(strCommand);
    //             }

    //             // Pos must be within range
    //             if (n > ptcpipsrv->m_commandArray.size()) {
    //                 n = ptcpipsrv->m_commandArray.size() - 1;
    //             }

    //             // Get the command
    //             strCommand =
    //               ptcpipsrv
    //                 ->m_commandArray[ptcpipsrv->m_commandArray.size() - n -
    //                 1];

    //             // Write out the command
    //             ptcpipsrv->write(conn,strCommand, true);
    //         }

    //         ptcpipsrv->m_commandArray.push_back(
    //           strCommand); // put at beginning of list
    //         if (ptcpipsrv->m_commandArray.size() >
    //             VSCP_TCPIP_COMMAND_LIST_MAX) {
    //             ptcpipsrv->m_commandArray
    //               .pop_front(); // Remove last inserted item
    //         }

    //         // Execute command
    //         if (VSCP_TCPIP_RV_CLOSE == ptcpipsrv->CommandHandler(strCommand))
    //         {
    //             break;
    //         }
    //     }

    // } // while

    // // Remove the client from the client queue
    // pthread_mutex_lock(&ptcpipsrv->m_pParent->m_mutexTcpClientList);
    // std::list<CTcpipSrv*>::iterator it;
    // for (it = ptcpipsrv->m_pParent->m_tcpip_clientList.begin();
    //      it != ptcpipsrv->m_pParent->m_tcpip_clientList.end();
    //      ++it) {

    //     CTcpipSrv* pclient                  = *it; // TODO check
    //     struct stcp_connection* stored_conn = pclient->m_conn;
    //     if (stored_conn->client.id == ptcpipsrv->m_conn->client.id) {
    //         ptcpipsrv->m_pParent->m_tcpip_clientList.erase(it);
    //         break;
    //     }
    // }
    // pthread_mutex_unlock(&ptcpipsrv->m_pParent->m_mutexTcpClientList);

    // // Close the connection
    // conn->is_closing = 1;
    // stcp_close_connection(ptcpipsrv->m_conn);
    // ptcpipsrv->m_conn = nullptr;

    // // Close the channel
    // ptcpipsrv->getClientItem()->setIsOpen(false);

    // // Remove the client from the Client List
    // // pthread_mutex_lock(m_mutexClientItemList);
    // //
    // ptcpipsrv->getControlObject()->removeClient(ptcpipsrv->getClientItem());
    // // pthread_mutex_unlock(m_mutexClientItemList);

    // // Delete the client object
    // delete ptcpipsrv;

    spdlog::info("[TCP/IP srv client thread] Exit.");

    return nullptr;
}
