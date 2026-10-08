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
#include <string>

#include <arpa/inet.h>
#include <canal-macro.h>
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
timer_fn(void* arg)
{
    struct mg_mgr* mgr       = (struct mg_mgr*)arg;
    CControlObject* pCtrlObj = (CControlObject*)mgr->userdata;

    // if (c_res.c == NULL) {
    //     c_res.i = 0;
    //     c_res.c = mg_connect(mgr, s_conn, cfn, &c_res);
    //     MG_INFO(("CLIENT %s", c_res.c ? "connecting" : "failed"));
    // }
}

///////////////////////////////////////////////////////////////////////////////
// CTcpipSrv
//
// This thread listens for connection on a TCP socket and starts a new thread
// to handle client requests
//

CTcpipSrv::CTcpipSrv(CControlObject* obj)
{
    m_pCtrlObj     = obj;   // Set the control object pointer
    m_bReceiveLoop = false; // Not in receive loop
    m_bRun         = true;  // Not quitting yet

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

    // Write out data
    m_rv = mg_send(conn, (const char*)str.c_str(), str.length());
    if (m_rv != str.length()) {
        return false;
    }

    return true;
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

    m_rv = mg_send(conn, (const char*)buf, len);
    if (m_rv != len) {
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

    //*********************************************************************
    //                             Rcvloop
    //*********************************************************************

    else if (commandStartsWith("rcvloop", true) ||
             commandStartsWith("receiveloop", true)) {
        if ((pUserItem != nullptr) &&
            pUserItem->isUserAllowed(VSCP_USER_RIGHT_ALLOW_RCV_EVENT)) {
            try {
                pClientItem->setReceiveLoopTimestamp(time(NULL));
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

    else if (commandStartsWith("quitloop", true)) {
        m_bReceiveLoop = false;
        write(conn, MSG_QUIT_LOOP, strlen(MSG_QUIT_LOOP));
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
        conn->is_draining = 1; // close after all pending data is sent
        // conn->is_closing = 1;
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
                // if (!m_pCtrlObj->sendEvent(pClientItem, pEvent)) {
                //     vscp_deleteEvent_v2(&pEvent);
                //     write(conn,
                //           MSG_UNABLE_TO_SEND_EVENT,
                //           strlen(MSG_UNABLE_TO_SEND_EVENT));
                //     return;
                // }

                vscp_deleteEvent_v2(&pEvent);
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

            // TODO have to send also
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
            // if (!m_pCtrlObj->sendEvent(pClientItem, pEvent)) {
            //     vscp_deleteEvent_v2(&pEvent);
            //     write(conn,
            //           MSG_UNABLE_TO_SEND_EVENT,
            //           strlen(MSG_UNABLE_TO_SEND_EVENT));
            //     return;
            // }

            vscp_deleteEvent_v2(&pEvent);
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
            // if (!m_pCtrlObj->sendEvent(pClientItem, pEvent)) {
            //     vscp_deleteEvent_v2(&pEvent);
            //     write(conn,
            //           MSG_UNABLE_TO_SEND_EVENT,
            //           strlen(MSG_UNABLE_TO_SEND_EVENT));
            //     return;
            // }

            vscp_deleteEvent_v2(&pEvent);
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
    vscpEvent event;

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

    // Get date/time - can be empty
    if (!tokens.empty()) {
        str = tokens.front();
        tokens.pop_front();
        vscp_trim(str);
        if (str.length()) {
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
                vscp_setEventDateTimeBlockToNow(&event);
            }
        }
        else {
            // set current time
            vscp_setEventDateTimeBlockToNow(&event);
        }
    }
    else {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    // Get Timestamp - can be empty
    if (!tokens.empty()) {
        str = tokens.front();
        tokens.pop_front();
        vscp_trim(str);
        if (str.length()) {
            event.timestamp = vscp_readStringValue(str);
        }
        else {
            event.timestamp = vscp_makeTimeStamp();
        }
    }
    else {
        write(conn, MSG_PARAMETER_ERROR, strlen(MSG_PARAMETER_ERROR));
        return;
    }

    // Get GUID
    std::string strGUID;
    if (!tokens.empty()) {

        strGUID = tokens.front();
        tokens.pop_front();

        // Parse the GUID string into the event's GUID structure
        vscp_guid_parse(event.GUID, strGUID.c_str(), nullptr);
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

    // send event
    // if (!m_pCtrlObj->sendEvent(pClientItem, &event)) {
    //     vscp_deleteEvent(&event); // Deallocate data
    //     write(conn, MSG_BUFFER_FULL, strlen(MSG_BUFFER_FULL));
    //     return;
    // }
    vscp_deleteEvent(&event); // Deallocate data

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

    if (pClientItem->getClientInputQueueSize() > 0) {

        // Get event
        vscpEvent* pev = pClientItem->getEventFromClientInputQueue(true);
        if (nullptr == pev) {
            spdlog::error("sendOneEventFromQueue: Failed to get event from "
                          "client input queue.");
            return false;
        }

        vscp_convertEventToString(strOut, pev);
        strOut += ("\r\n");
        write(conn, strOut.c_str(), strlen(strOut.c_str()));

        vscp_deleteEvent_v2(&pev);
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

    sprintf(outbuf,
            "%zd\r\n%s",
            pClientItem->getClientInputQueueSize(),
            MSG_OK);
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

    pClientItem->clearClientInputQueue();

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

    // pthread_mutex_lock(&m_pCtrlObj->m_mutex_UserList);
    // pClientItem->setUserItem(m_pCtrlObj->m_userList.validateUser(
    //   pUserItem->getUserName().c_str(),
    //   strPassword));
    // pthread_mutex_unlock(&m_pCtrlObj->m_mutex_UserList);

    if (!pUserItem->validatePassword(strPassword)) {

        std::string strErr = vscp_str_format(
          ("[TCP/IP srv] User [%s][%s] not allowed to connect.\n"),
          (const char*)pUserItem->getUserName().c_str(),
          (const char*)strPassword.c_str());

        spdlog::error("%s", strErr.c_str());
        write(conn, MSG_PASSWORD_ERROR, strlen(MSG_PASSWORD_ERROR));
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

    spdlog::error("{}", strErr.c_str());

    pClientItem->setAuthenticated(true);

    //pClientItem->setUserItem(nullptr);
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

    vscp_trim(getCurrentCommand());

    // pClientItem->clearSessionId();
    // if (!m_pCtrlObj->generateSessionId(
    //       (const char*)getCurrentCommand().c_str(),
    //       pClientItem->getSessionId().c_str())) {
    //     write(conn,
    //           MSG_FAILED_TO_GENERATE_SID,
    //           strlen(MSG_FAILED_TO_GENERATE_SID));
    //     return;
    // }

    str = std::string("+OK - ") +
          std::string(pClientItem->getSessionId().c_str()) +
          std::string("\r\n");
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

    m_bReceiveLoop = true; // Mark connection as being in receive loop

    // Notify the client that it has entered the receive loop
    write(conn, MSG_RECEIVE_LOOP, strlen(MSG_RECEIVE_LOOP));

    // Clear the read buffer before entering the receive loop
    // pClientItem->clearReadBuffer();

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
    // pthread_mutex_lock(&m_pCtrlObj->getClientList().m_mutexClientItemList);

    // std::deque<CClientItem*>::iterator it;
    // for (it = m_pCtrlObj->getClientList().m_itemList.begin();
    //      it != m_pCtrlObj->getClientList().m_itemList.end();
    //      ++it) {

    //     CClientItem* pItem = *it;

    //     pItem->getInterfaceGUID().toString(strGUID);
    //     strBuf = vscp_str_format("%d,", pItem->getClientID());
    //     strBuf += vscp_str_format("%d,", pItem->getInterfaceType());
    //     strBuf += strGUID;
    //     strBuf += std::string(",");
    //     strBuf += pItem->getDeviceName().c_str();
    //     strBuf += std::string(" | Started at ");
    //     strBuf += pItem->getDateUtcStarted().getISODateTime();
    //     strBuf += std::string("\r\n");

    //     write(conn, strBuf);
    // }

    write(conn, MSG_OK, strlen(MSG_OK));

    // pthread_mutex_unlock(&m_pCtrlObj->getClientList().m_mutexClientItemList);
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
               "command'\r\n";
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
        str += "DRIVER            - Driver manipulation.\r\n";
        str += "INTERFACE         - Interface handling. \r\n";
        str += "WCYD/WHATCANYOUDO - Check server capabilities. \r\n";
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
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("info", true)) {
        std::string str = "'INFO' - Get status information.\r\n";
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
        std::string str = "'INTERFACE' Handle interfaces on the daemon.\r\n";
        str += "'INTERFACE list'.\r\n";
        str += "'INTERFACE close'.\r\n";
        write(conn, (const char*)str.c_str(), str.length());
    }
    else if (commandStartsWith("wcyd", true) ||
             commandStartsWith("whatcanyoudo", true)) {
        std::string str = "'WCYD/WHATCANYOUDO' Return the VSCP server "
                          "capabilities 64-bit array.\r\n";
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
    // Get client item
    CClientItem* pClientItem = static_cast<CClientItem*>(conn->fn_data);
    if (nullptr == pClientItem) {
        spdlog::error("[TCP/IP srv client thread] Error, "
                      "Client thread TCP/IP server object not initialized.");
        return;
    }

    // Get the TCP/IP server object from the thread data.
    CControlObject* pobj = pClientItem->getControlObject();
    if (nullptr == pobj) {
        spdlog::error("[TCP/IP srv client thread] Error, "
                      "Client thread control object not initialized.");
        return;
    }

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

        // Mark as connected
        newClient->setConnected(true);

        // Addd to connectd list
        if (!pobj->addClient(newClient)) {
            mg_send(conn, MSG_INTERNAL_ERROR, strlen(MSG_INTERNAL_ERROR));
            spdlog::error("Failed to add new client to the server");
            delete newClient;
            conn->is_closing = 1;
            return;
        }

        // Associate the new client item with the connection
        conn->fn_data = newClient;

        // Greet the new client
        mg_send(conn, MSG_WELCOME, sizeof(MSG_WELCOME));
        mg_send(conn, VSCPD_DISPLAY_VERSION, sizeof(VSCPD_DISPLAY_VERSION));
        mg_send(conn, "\r\n", 2);
        mg_send(conn, VSCPD_COPYRIGHT, sizeof(VSCPD_COPYRIGHT));
        mg_send(conn, "\r\n", 2);
        mg_send(conn, MSG_OK, sizeof(MSG_OK));
        spdlog::debug("SERVER sent welcome message");
    }

    else if (ev == MG_EV_READ) {
        struct mg_iobuf* r = &conn->recv;
        spdlog::trace("-->SERVER got data: <{}>",
                      std::string((const char*)r->buf, r->len));

        // Find "\r\n" sequence in the received data
        char* eol = (char*)memmem(r->buf, r->len, "\r\n", 2);
        if (eol) {
            spdlog::trace("Found end of line at position {}",
                          eol - (char*)r->buf);
        }

        if (eol) {
            // Null-terminate the line at the end of line sequence
            *eol = '\0';
            spdlog::trace("Processed line: {}", (char*)r->buf);

            // Copy the processed line to a separate buffer if needed
            char line[2048];
            size_t line_len = 0; // Used length
            size_t save_len = 0; // Consumed length
            save_len = line_len = eol - (char*)r->buf;
            if (line_len >= sizeof(line)) {
                line_len = sizeof(line) - 1;
            }
            memcpy(line, r->buf, line_len);
            line[line_len] = '\0';

            // Remove consumed data from the buffer
            mg_iobuf_del(r, 0, save_len + 2); // Remove \r\n also

            spdlog::trace("Consumed {} bytes from the buffer", save_len);
            spdlog::trace("Processed line: {}", line);

            // Save the current command
            pobj->getTcpipSrv().setCurrentCommand(std::string(line));

            // Here you can process the line as needed, for example:
            pobj->getTcpipSrv().commandHandler(conn, std::string(line));
        }

        // mg_send(conn, r->buf, r->len); // echo it back
        // r->len = 0; // Tell Mongoose we've consumed the data
    }
    else if (ev == MG_EV_CLOSE) {
        // Mark as disconnected
        if (nullptr != pClientItem) {
            pobj->getClientList().removeClient((CClientItem*)pClientItem);
        }
        conn->is_closing = 1; // Ensure the connection is marked as closing
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
    struct mg_mgr mgr; // Event manager
    struct mg_connection* conn;

    mg_log_set(MG_LL_INFO); // Set log level
    mg_mgr_init(&mgr);      // Initialize event manager
    mgr.userdata = pdata;

    // // Add a timer to the Mongoose event manager
    mg_timer_add(&mgr,
                 15000,
                 MG_TIMER_REPEAT | MG_TIMER_RUN_NOW,
                 timer_fn,
                 &mgr);

    // Start to listen for connections
    spdlog::debug("Starting TCP/IP server on interface: {}",
                  ptcpipsrv->getInterfaceAddress().c_str());
    conn = mg_listen(&mgr,
                     ptcpipsrv->getInterfaceAddress().c_str(),
                     tcpip_event_handler,
                     pdata); // Create server connection
    if (conn == NULL) {
        MG_INFO(("SERVER cant' open a connection"));
        return nullptr;
    }

    // Event loop
    while (ptcpipsrv->isWorking()) {
        mg_mgr_poll(&mgr, 100); // Poll the event manager
    }

    mg_mgr_free(&mgr); // Free the event manager resources

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
    // CTcpipSrv* ptcpipsrv = (CTcpipSrv*)pData;
    // if (NULL == ptcpipsrv) {
    // if (nullptr == ptcpipsrv) {
    //                   "Client thread object not initialized.");

    //     return nullptr;

    // if (nullptr == ptcpipsrv->m_pParent) {
    //     spdlog::error("[TCP/IP srv client thread] Error, "
    //                   "Control object not initialized.");
    //     return nullptr;
    // }

    // spdlog::debug("[TCP/IP srv client thread] Thread started.");

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
