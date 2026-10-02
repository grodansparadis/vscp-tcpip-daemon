// ClientList.cpp: implementation of the CClientList class.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP (https://www.vscp.org)
//
// Copyright (C) 2000-2026 Ake Hedman,
// the VSCP project, <info@vscp.org>
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

#define _POSIX

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef WIN32
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
// _WINSOCK_DEPRECATED_NO_WARNINGS is already defined by mongoose.h
// #ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
// #define _WINSOCK_DEPRECATED_NO_WARNINGS
// #endif
#include <pch.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#endif

#include <canal-macro.h>
#include <vscp.h>
#include <vscpdatetime.h>
#include <vscphelper.h>

#include "clientlist.h"

#include "mongoose.h"

#include <mustache.hpp>
#include <nlohmann/json.hpp> // Needs C++11  -std=c++11

// https://github.com/nlohmann/json
using json = nlohmann::json;

using namespace kainjow::mustache;

#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <string>

const char* interface_description[] = { "Unknown (you should not see this).",
                                        "Internal VSCP server client.",
                                        "Level I (CANAL) Driver.",
                                        "Level II Driver.",
                                        "TCP/IP Client.",
                                        "UDP Client.",
                                        "Web Server Client.",
                                        "WebSocket Client.",
                                        "REST client",
                                        "Multicast client",
                                        "Multicast channel client",
                                        "MQTT client",
                                        "COAP client",
                                        "Discovery client",
                                        "JavaScript client",
                                        "Lua client",
                                        NULL };

class CControlObject;


///////////////////////////////////////////////////////////////////////////////
// CClientItem
//

CClientItem::CClientItem()
{
    m_status.channel_status      = 0;
    m_clientID                   = 0;
    m_type                       = CLIENT_ITEM_INTERFACE_TYPE_NONE;
    m_maxItemsInClientInputQueue = CLIENT_ITEM_MAX_INPUT_QUEUE;
    m_pCtrlObj                   = NULL;
    m_conn                       = NULL;
    m_bConnected                 = false;

    m_dtutc = vscpdatetime::UTCNow();

    // Create semaphores for the client input queue and event send
#ifdef WIN32
    m_semClientInputQueue = CreateSemaphore(NULL, 0, 100, NULL);
    m_hEventSend          = CreateSemaphore(NULL, 0, 100, NULL);
#else
    sem_init(&m_semClientInputQueue, 0, 0);
    sem_init(&m_hEventSend, 0, 0);
#endif
    pthread_mutex_init(&m_mutexClientInputQueue, NULL);

    /*!
        Initialize the GUID to nil (all zeros)
    */
    m_guid.clear();

    // Nil Level II mask (accept all)
    vscp_clearVSCPFilter(&m_filter);

    // Nil statistics (all counters set to zero)
    memset(&m_statistics, 0, sizeof(m_statistics));

    // Nil status (all fields set to zero)
    memset(&m_status, 0, sizeof(m_status));

    m_pUserItem = NULL; // No user connected to this client yet
}

CClientItem::CClientItem(CControlObject* pControl,
                         CLIENT_ITEM_INTERFACE_TYPE type,
                         struct mg_connection* conn)
  : CClientItem()
{
    m_pCtrlObj = pControl;
    m_type     = type;
    m_conn     = conn;
}

///////////////////////////////////////////////////////////////////////////////
// ~CClientItem
//

CClientItem::~CClientItem()
{
    // Clear the input queue
    clearInputQueue();

#ifdef WIN32
    CloseHandle(m_hEventSend);
    CloseHandle(m_semClientInputQueue);
#else
    sem_destroy(&m_hEventSend);
    sem_destroy(&m_semClientInputQueue);
#endif

    pthread_mutex_destroy(&m_mutexClientInputQueue);
}

///////////////////////////////////////////////////////////////////////////////
// isConnected
//

bool
CClientItem::isConnected(void)
{
    return (NULL != m_conn) && m_bConnected && !m_conn->is_closing;
}

///////////////////////////////////////////////////////////////////////////////
// clearClientInputQueue
//

void
CClientItem::clearClientInputQueue(void)
{
    pthread_mutex_lock(&m_mutexClientInputQueue);
    // Remove and delete all events in the queue
    while (!m_clientInputQueue.empty()) {
        vscpEvent* pEvent = m_clientInputQueue.front();
        m_clientInputQueue.pop_front();
        if (NULL != pEvent) {
            vscp_deleteEvent(pEvent);
        }
    }
    pthread_mutex_unlock(&m_mutexClientInputQueue);
}


///////////////////////////////////////////////////////////////////////////////
// getEventFromClientInputQueue
//

vscpEvent*
CClientItem::getEventFromClientInputQueue(bool bRemove)
{
    vscpEvent* pEvent = NULL;

    pthread_mutex_lock(&m_mutexClientInputQueue);
    if (!m_clientInputQueue.empty()) {
        pEvent = m_clientInputQueue.front();
        if (bRemove) {
            m_clientInputQueue.pop_front();
        }
    }
    pthread_mutex_unlock(&m_mutexClientInputQueue);

    return pEvent;
}

///////////////////////////////////////////////////////////////////////////////
// setDeviceName
//

void
CClientItem::setDeviceName(const std::string& name)
{
    m_strDeviceName = name;
    m_strDeviceName += "|Started at ";

    m_strDeviceName += vscpdatetime::Now().getISODateTime();
}

///////////////////////////////////////////////////////////////////////////////
// getAsString
//
// "id,type,GUID,name,dt-created(UTC),open-flag, flags"

std::string
CClientItem::getClientItemAsString(void)
{
    std::string str;

    str = vscp_str_format("%ud,", m_clientID);
    str += vscp_str_format("%d,", m_type);
    str += m_guid.toString();
    str += ",";
    str += m_strDeviceName;
    str += ",";
    str += m_dtutc.getISODateTime();
    str += ",";
    str += m_bOpen ? "true" : "false";
    str += ",";
    str += vscp_str_format("%ul", m_flags);

    return str;
}

///////////////////////////////////////////////////////////////////////////////
// addEventToInputQueue
//

bool
CClientItem::addEventToInputQueue(vscpEvent* pEvent)
{
    if (NULL == pEvent) {
        return false;
    }
    // Mutex handle that is used for sharing of the client object
    pthread_mutex_lock(&m_mutexClientInputQueue);
    m_clientInputQueue.push_back(pEvent);
    pthread_mutex_unlock(&m_mutexClientInputQueue);
    // Signal that an event has been added to the input queue
#ifdef WIN32
    SetEvent(m_semClientInputQueue);
#else
    sem_post(&m_semClientInputQueue);
#endif
    return true;
}

///////////////////////////////////////////////////////////////////////////////
// getEventFromInputQueue
//

vscpEvent*
CClientItem::getEventFromInputQueue(void)
{
    vscpEvent* pEvent = NULL;

    pthread_mutex_lock(&m_mutexClientInputQueue);
    if (!m_clientInputQueue.empty()) {
        pEvent = m_clientInputQueue.front();
        m_clientInputQueue.pop_front();
    }
    pthread_mutex_unlock(&m_mutexClientInputQueue);

    return pEvent;
}

///////////////////////////////////////////////////////////////////////////////
// clearInputQueue
//

void
CClientItem::clearInputQueue(void)
{
    // Lock the input queue mutex before clearing the queue
    pthread_mutex_lock(&m_mutexClientInputQueue);
    std::deque<vscpEvent*>::iterator iter;
    for (iter = m_clientInputQueue.begin(); iter != m_clientInputQueue.end();
         ++iter) {
        vscpEvent* pEvent = *iter;
        vscp_deleteEvent_v2(&pEvent);
    }
    m_clientInputQueue.clear();
    pthread_mutex_unlock(&m_mutexClientInputQueue);
}

///////////////////////////////////////////////////////////////////////////////
// CommandStartWith
//

bool
CClientItem::CommandStartsWith(const std::string& cmd, bool bFix)
{
    if (!vscp_startsWith(vscp_upper(m_currentCommand), vscp_upper(cmd))) {
        return false;
    }

    // If asked to do so remove the command.
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

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// compareClientItems
//
// Type of compare function for list sort operation (as in 'qsort')
//

static bool
compareClientItems(const uint16_t element1, const uint16_t element2)
{
    return (element1 < element2);
}

///////////////////////////////////////////////////////////////////////////////
// Construction/Destruction
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// CClientList
//

CClientList::CClientList()
{
    pthread_mutex_init(&m_mutexClientItemList, NULL);
}

///////////////////////////////////////////////////////////////////////////////
// ~CClientList
//

CClientList::~CClientList()
{
    // Clear the client output queue
    std::deque<vscpEvent*>::iterator iter;
    pthread_mutex_lock(&m_mutex_ClientOutputQueue);
    for (iter = m_clientOutputQueue.begin(); iter != m_clientOutputQueue.end(); ++iter) {
        vscpEvent* pEvent = *iter;
        vscp_deleteEvent_v2(&pEvent);
    }
    m_clientOutputQueue.clear();
    pthread_mutex_unlock(&m_mutex_ClientOutputQueue);

    removeAllClients();
    pthread_mutex_destroy(&m_mutexClientItemList);

     if (0 != sem_destroy(&m_semClientOutputQueue)) {
        spdlog::error("Unable to destroy m_semClientOutputQueue");
    }

    if (0 != sem_destroy(&m_semSentToAllClients)) {
        spdlog::error("Unable to destroy m_semSentToAllClients");
    }

    if (0 != pthread_mutex_destroy(&m_mutex_ClientOutputQueue)) {
        spdlog::error("Unable to destroy m_mutex_ClientOutputQueue");
        return;
    }
}

///////////////////////////////////////////////////////////////////////////////
// findFreeId
//

bool
CClientList::findFreeId(uint16_t* pid)
{
    std::list<uint16_t> sorterIdList;
    std::deque<CClientItem*>::iterator it;

    // Check pointer
    if (NULL == pid) {
        return false;
    }

    // Find next free id
    for (it = m_itemList.begin(); it != m_itemList.end(); ++it) {
        CClientItem* pItem = *it;
        sorterIdList.push_back(pItem->getClientID());
    }

    // Sort list on client id
    sorterIdList.sort(compareClientItems);

    std::list<uint16_t>::iterator it_id;
    for (it_id = sorterIdList.begin(); it_id != sorterIdList.end(); ++it_id) {
        // As the list is sorted on id we have found an
        // unused id if the id is higher than the counter
        if (*pid < *it_id) {
            break;
        }

        (*pid)++;
        if (0 == *pid) {
            return false; // All client id's are in use
        }
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// addClient
//

bool
CClientList::addClient(CClientItem* pClientItem, uint32_t id)
{
    // Check pointer
    if (NULL == pClientItem) {
        return false;
    }

    pClientItem->setClientID(id ? id : 1);

    if (0 == id) {
        if (!findFreeId(&pClientItem->m_clientID)) {
            return false;
        }
    }

    // We try to assign requested id
    std::deque<CClientItem*>::iterator it;
    for (it = m_itemList.begin(); it != m_itemList.end(); ++it) {

        CClientItem* pItem = *it;

        // If id is already in use fail
        if (pClientItem->getClientID() == pItem->getClientID()) {
            return false;
        }
    }

    // Append to list
    m_itemList.push_back(pClientItem);

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// addClient
//

bool
CClientList::addClient(CClientItem* pClientItem, cguid& guid)
{
    // Check pointer
    if (NULL == pClientItem) {
        return false;
    }

    if (!addClient(pClientItem)) {
        return false;
    }

    // Set the guid
    pClientItem->setGuid(guid);

    // Make sure nickname id is zero
    pClientItem->getGuid().setNicknameID(0);

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// removeClient
//

bool
CClientList::removeClient(CClientItem* pClientItem)
{
    // Must be a valid pointer
    if (NULL == pClientItem) {
        spdlog::error("removeClient in clientlist but clinet obj is NULL");
        return false;
    }

    std::deque<vscpEvent*>::iterator iter;
    for (iter = pClientItem->m_clientInputQueue.begin();
         iter != pClientItem->m_clientInputQueue.end();
         ++iter) {
        vscpEvent* pEvent = *iter;
        vscp_deleteEvent_v2(&pEvent);
    }
    pClientItem->m_clientInputQueue.clear();

    // Take away the node
    for (std::deque<CClientItem*>::iterator it = m_itemList.begin();
         it != m_itemList.end();
         ++it) {
        if (*it == pClientItem) {
            m_itemList.erase(it);
            delete pClientItem;
            return true;
        }
    }

    return false;
}

bool
CClientList::removeAllClients()
{
    pthread_mutex_lock(&m_mutexClientItemList);
    // Empty the client list
    std::deque<CClientItem*>::iterator it;
    for (it = m_itemList.begin(); it != m_itemList.end(); ++it) {
        removeClient(*it);
        delete *it;
    }
    m_itemList.clear();
    pthread_mutex_unlock(&m_mutexClientItemList);

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// getClientFromId
//

CClientItem*
CClientList::getClientFromId(uint16_t id)
{
    std::deque<CClientItem*>::iterator it;
    CClientItem* returnItem = NULL;

    for (it = m_itemList.begin(); it != m_itemList.end(); ++it) {

        CClientItem* pItem = *it;
        if (pItem->getClientID() == id) {
            returnItem = pItem;
            break;
        }
    }

    return returnItem;
}

///////////////////////////////////////////////////////////////////////////////
// getClientFromOrdinal
//

CClientItem*
CClientList::getClientFromOrdinal(uint16_t ordinal)
{
    if (!m_itemList.size()) {
        return NULL;
    }

    if (ordinal > (m_itemList.size() - 1)) {
        return NULL;
    }

    return m_itemList[ordinal];
}

///////////////////////////////////////////////////////////////////////////////
// getClientFromGUID
//

CClientItem*
CClientList::getClientFromGUID(cguid& guid)
{
    std::deque<CClientItem*>::iterator it;
    CClientItem* returnItem = NULL;

    for (it = m_itemList.begin(); it != m_itemList.end(); ++it) {

        CClientItem* pItem = *it;
        if (pItem->getGuid() == guid) {
            returnItem = pItem;
            break;
        }
    }

    return returnItem;
}

///////////////////////////////////////////////////////////////////////////////
// getAllInterfacesAsString
//

std::string
CClientList::getAllClientsAsString(void)
{
    std::string str;

    pthread_mutex_lock(&m_mutexClientItemList);

    std::deque<CClientItem*>::iterator it;
    for (it = m_itemList.begin(); it != m_itemList.end(); ++it) {
        CClientItem* pItem = *it;
        str += pItem->getAsString();
        str += "\r\n";
    }

    pthread_mutex_unlock(&m_mutexClientItemList);

    return str;
}

///////////////////////////////////////////////////////////////////////////////
// getClient
//

bool
CClientList::getClient(uint16_t n, std::string& client)
{
    if (!m_itemList.size()) {
        return false;
    }

    if (n > (m_itemList.size() - 1)) {
        return false;
    }

    CClientItem* pClient = m_itemList[n];
    if (NULL == pClient) {
        return false;
    }

    client = pClient->getAsString();

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// sendEventToClient
//

bool
CClientList::sendEventToClient(CClientItem* pClientItem,
                               const vscpEvent* pEvent)
{
    // Must be valid pointers
    if (NULL == pClientItem) {
        spdlog::error("sendEventToClient - Pointer to clientitem is null");
        return false;
    }

    if (NULL == pEvent) {
        spdlog::error("sendEventToClient - Pointer to event is null");
        return false;
    }

    // Check if filtered out - if so do nothing here
    if (!vscp_doLevel2Filter(pEvent, &pClientItem->getFilter())) {
        spdlog::debug("sendEventToClient - Filtered out");
        return false;
    }

    // If the client queue is full for this client then the
    // client will not receive the message
    // (max set to zero means any number of events can be collected)
    if (pClientItem->getMaxItemsInClientInputQueue() &&
        (pClientItem->getClientInputQueueSize() >
         pClientItem->getMaxItemsInClientInputQueue())) {
        spdlog::info("sendEventToClient - overrun");
        // Overrun
        pClientItem->getStatistics().cntOverruns++;
        return false;
    }

    // Create a new event
    vscpEvent* pnewvscpEvent = new vscpEvent;
    if (NULL != pnewvscpEvent) {

        // Copy in the new event
        if (!vscp_copyEvent(pnewvscpEvent, pEvent)) {
            vscp_deleteEvent_v2(&pnewvscpEvent);
            spdlog::error("sendEventToClient - Failed to copy event");
            return false;
        }

        // Add the new event to the input queue
        pthread_mutex_lock(&pClientItem->getMutexClientInputQueue());
        pClientItem->getClientInputQueue().push_back(pnewvscpEvent);
        pthread_mutex_unlock(&pClientItem->getMutexClientInputQueue());
#ifdef WIN32
        ReleaseSemaphore(pClientItem->getSemClientInputQueue(), 1, NULL);
#else
        sem_post(&pClientItem->getSemClientInputQueue());
#endif
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// sendEventAllClients
//

bool
CClientList::sendEventAllClients(const vscpEvent* pEvent, uint32_t excludeID)
{
    CClientItem* pClientItem;
    std::deque<CClientItem*>::iterator it;

    if (NULL == pEvent) {
        spdlog::error("sendEventAllClients - null event");
        return false;
    }

    pthread_mutex_lock(&m_mutexClientItemList);
    for (it = m_itemList.begin(); it != m_itemList.end(); ++it) {
        pClientItem = *it;

        if ((NULL != pClientItem) &&
            (excludeID != pClientItem->getClientID())) {
            spdlog::debug("Send event to client [{}]",
                          pClientItem->getDeviceName());
            if (!sendEventToClient(pClientItem, pEvent)) {
            }
        }
    }
    pthread_mutex_unlock(&m_mutexClientItemList);

    return true;
}