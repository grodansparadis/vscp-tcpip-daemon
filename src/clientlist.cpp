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
#include "controlobject.h"

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

///////////////////////////////////////////////////////////////////////////////
// CClientItem
//

CClientItem::CClientItem()
{
    m_status.channel_status = 0;
    m_clientID              = 0;
    m_flags                 = 0;
    m_type                  = CLIENT_ITEM_INTERFACE_TYPE_NONE;
    m_pCtrlObj              = NULL;
    m_conn                  = NULL;
    m_bConnected            = false;
    m_bAuthenticated        = false;
    m_bReceiveLoop          = false;

    m_dtutc = vscpdatetime::UTCNow();

    // Create semaphores for the client input queue and event send
#ifdef WIN32
    m_semSendQueue = CreateSemaphore(NULL, 0, 100, NULL);
    m_hEventSend   = CreateSemaphore(NULL, 0, 100, NULL);
#else
    sem_init(&m_semSendQueue, 0, 0);
    sem_init(&m_hEventSend, 0, 0);
#endif
    pthread_mutex_init(&m_mutexSendQueue, NULL);

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

    // Generate session ID
    char sid[32] = { 0 };
    char buf[65] = { 0 };
    mg_random(sid, sizeof(sid));
    for (size_t i = 0; i < sizeof(sid); i++) {
        mg_snprintf(buf + i * 2, 3, "%02x", sid[i]);
    }
    setSessionId(buf);

    m_userItem.reset(); // No user connected to this client yet
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
    clearSendQueue();

#ifdef WIN32
    CloseHandle(m_hEventSend);
    CloseHandle(m_semSendQueue);
#else
    sem_destroy(&m_hEventSend);
    sem_destroy(&m_semSendQueue);
#endif

    pthread_mutex_destroy(&m_mutexSendQueue);
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
// clearSendQueue
//

void
CClientItem::clearSendQueue(void)
{
    // Lock the send queue mutex before clearing the queue
    pthread_mutex_lock(&m_mutexSendQueue);
    std::deque<vscpEvent*>::iterator iter;
    for (iter = m_sendQueue.begin(); iter != m_sendQueue.end(); ++iter) {
        vscpEvent* pEvent = *iter;
        vscp_deleteEvent_v2(&pEvent);
    }
    m_sendQueue.clear();
    pthread_mutex_unlock(&m_mutexSendQueue);
}

///////////////////////////////////////////////////////////////////////////////
// getClientSendQueueSize
//

size_t
CClientItem::getClientSendQueueSize(void)
{
    size_t size;
    pthread_mutex_lock(&m_mutexSendQueue);
    size = m_sendQueue.size();
    pthread_mutex_unlock(&m_mutexSendQueue);
    return size;
}

///////////////////////////////////////////////////////////////////////////////
// waitForSendQueueEvent
//

int
CClientItem::waitForSendQueueEvent(uint32_t timeoutMs)
{
    return vscp_sem_wait(&m_semSendQueue, timeoutMs);
}

///////////////////////////////////////////////////////////////////////////////
// getEventFromSendQueue
//

vscpEvent*
CClientItem::getEventFromSendQueue(bool bRemove)
{
    vscpEvent* pEvent = NULL;

    pthread_mutex_lock(&m_mutexSendQueue);
    if (!m_sendQueue.empty()) {
        pEvent = m_sendQueue.front();
        if (bRemove) {
            m_sendQueue.pop_front();
        }
    }
    else {
        // No event in the send queue
        spdlog::debug("getEventFromSendQueue: No event in the send queue");
    }
    pthread_mutex_unlock(&m_mutexSendQueue);

    return pEvent;
}

///////////////////////////////////////////////////////////////////////////////
// setDeviceName
//

void
CClientItem::setDeviceName(const std::string& name)
{
    m_strDeviceName = name;
    // m_strDeviceName += " | Started at ";
    // m_strDeviceName += vscpdatetime::Now().getISODateTime();
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
// addEventToSendQueue
//

bool
CClientItem::addEventToSendQueue(vscpEvent* pEvent)
{
    if (NULL == pEvent) {
        return false;
    }
    // Mutex handle that is used for sharing of the client object
    pthread_mutex_lock(&m_mutexSendQueue);
    if (m_sendQueue.size() >= CLIENT_ITEM_MAX_SEND_QUEUE_SIZE) {
        pthread_mutex_unlock(&m_mutexSendQueue);
        return false;
    }
    m_sendQueue.push_back(pEvent);
    pthread_mutex_unlock(&m_mutexSendQueue);

    // // TX Statistics
    m_statistics.cntTransmitData += pEvent->sizeData;
    m_statistics.cntTransmitFrames++;

    // Signal that an event has been added to the send queue
#ifdef WIN32
    SetEvent(m_semSendQueue);
#else
    sem_post(&m_semSendQueue);
#endif
    return true;
}

///////////////////////////////////////////////////////////////////////////////
// getEventFromSendQueue
//

vscpEvent*
CClientItem::getEventFromSendQueue(void)
{
    vscpEvent* pEvent = NULL;

    pthread_mutex_lock(&m_mutexSendQueue);
    if (!m_sendQueue.empty()) {
        pEvent = m_sendQueue.front();
        m_sendQueue.pop_front();
    }
    pthread_mutex_unlock(&m_mutexSendQueue);

    return pEvent;
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
#ifdef WIN32
    m_semClientMainReceiveQueue = CreateSemaphore(NULL, 0, 0x7fffffff, NULL);
#else
    sem_init(&m_semClientMainReceiveQueue, 0, 0);
#endif
    sem_init(&m_semSentToAllClients, 0, 0);
    pthread_mutex_init(&m_mutex_ClientMainReceiveQueue, NULL);
    pthread_mutex_init(&m_mutexClientItemList, NULL);
}

///////////////////////////////////////////////////////////////////////////////
// ~CClientList
//

CClientList::~CClientList()
{
    // Remove all events from main receive queue
    clearClientMainReceiveQueue();

    // Remove all clients
    removeAllClients();
    pthread_mutex_destroy(&m_mutexClientItemList);

#ifdef WIN32
    CloseHandle(m_semClientMainReceiveQueue);
#else
    if (0 != sem_destroy(&m_semClientMainReceiveQueue)) {
        spdlog::error("Unable to destroy m_semClientMainReceiveQueue");
    }
#endif

    if (0 != sem_destroy(&m_semSentToAllClients)) {
        spdlog::error("Unable to destroy m_semSentToAllClients");
    }

    if (0 != pthread_mutex_destroy(&m_mutex_ClientMainReceiveQueue)) {
        spdlog::error("Unable to destroy m_mutex_ClientMainReceiveQueue");
        return;
    }
}

///////////////////////////////////////////////////////////////////////////////
// enqueueReceiveEvent
//

bool
CClientList::enqueueReceiveEvent(vscpEvent* pEvent)
{
    if (NULL == pEvent) {
        return false;
    }

    pthread_mutex_lock(&m_mutex_ClientMainReceiveQueue);
    if (CLIENT_MAIN_RECEIVE_QUEUE_MAX_SIZE <= m_clientMainReceiveQueue.size()) {
        pthread_mutex_unlock(&m_mutex_ClientMainReceiveQueue);
        return false;
    }
    m_clientMainReceiveQueue.push_back(pEvent);
    pthread_mutex_unlock(&m_mutex_ClientMainReceiveQueue);

    notifyClientMainReceiveQueueEvent();
    return true;
}

///////////////////////////////////////////////////////////////////////////////
// getEventFromClientMainReceiveQueue
//

vscpEvent*
CClientList::getEventFromClientMainReceiveQueue(bool remove)
{
    vscpEvent* pEvent = NULL;

    pthread_mutex_lock(&m_mutex_ClientMainReceiveQueue);
    if (!m_clientMainReceiveQueue.empty()) {
        pEvent = m_clientMainReceiveQueue.front();
        if (remove) {
            m_clientMainReceiveQueue.pop_front();
        }
    }
    pthread_mutex_unlock(&m_mutex_ClientMainReceiveQueue);

    return pEvent;
}

///////////////////////////////////////////////////////////////////////////////
// waitForClientMainReceiveQueueEvent
//

int
CClientList::waitForClientMainReceiveQueueEvent(uint32_t timeoutMs)
{
    return vscp_sem_wait(&m_semClientMainReceiveQueue, timeoutMs);
}

///////////////////////////////////////////////////////////////////////////////
// notifyClientMainReceiveQueueEvent
//

void
CClientList::notifyClientMainReceiveQueueEvent(void)
{
#ifdef WIN32
    if (!ReleaseSemaphore(m_semClientMainReceiveQueue, 1, NULL)) {
#else
    if (0 != sem_post(&m_semClientMainReceiveQueue)) {
#endif
        spdlog::error("Unable to signal the client main receive queue");
    }
}

///////////////////////////////////////////////////////////////////////////////
// clearClientMainReceiveQueue
//

void
CClientList::clearClientMainReceiveQueue(void)
{
    pthread_mutex_lock(&m_mutex_ClientMainReceiveQueue);
    while (!m_clientMainReceiveQueue.empty()) {
        vscpEvent* pEvent = m_clientMainReceiveQueue.front();
        m_clientMainReceiveQueue.pop_front();
        vscp_deleteEvent_v2(&pEvent);
    }
    pthread_mutex_unlock(&m_mutex_ClientMainReceiveQueue);
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
    if (NULL == pClientItem) {
        return false;
    }

    pthread_mutex_lock(&m_mutexClientItemList);
    uint16_t clientID = id ? id : 1;

    if (0 == id) {
        if (!findFreeId(&clientID)) {
            pthread_mutex_unlock(&m_mutexClientItemList);
            return false;
        }
    }
    pClientItem->setClientID(clientID);

    // We try to assign requested id
    std::deque<CClientItem*>::iterator it;
    for (it = m_itemList.begin(); it != m_itemList.end(); ++it) {

        CClientItem* pItem = *it;

        // If id is already in use fail
        if (pClientItem->getClientID() == pItem->getClientID()) {
            pthread_mutex_unlock(&m_mutexClientItemList);
            return false;
        }
    }

    // Append to list
    m_itemList.push_back(pClientItem);
    pthread_mutex_unlock(&m_mutexClientItemList);

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
    pClientItem->setInterfaceGUID(guid);

    // Make sure nickname id is zero
    cguid clientGuid = pClientItem->getInterfaceGUID();
    clientGuid.setNicknameID(0);
    pClientItem->setInterfaceGUID(clientGuid);

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

    pthread_mutex_lock(&m_mutexClientItemList);
    pClientItem->clearSendQueue();

    // Take away the node
    for (std::deque<CClientItem*>::iterator it = m_itemList.begin();
         it != m_itemList.end();
         ++it) {
        if (*it == pClientItem) {
            m_itemList.erase(it);
            pthread_mutex_unlock(&m_mutexClientItemList);
            delete pClientItem;
            return true;
        }
    }

    pthread_mutex_unlock(&m_mutexClientItemList);
    return false;
}

bool
CClientList::removeAllClients()
{
    pthread_mutex_lock(&m_mutexClientItemList);
    while (!m_itemList.empty()) {
        CClientItem* pClientItem = m_itemList.front();
        m_itemList.pop_front();
        pClientItem->clearSendQueue();
        delete pClientItem;
    }
    pthread_mutex_unlock(&m_mutexClientItemList);

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// getClientFromId
//

const CClientItem*
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

const CClientItem*
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

const CClientItem*
CClientList::getClientFromGUID(cguid& guid)
{
    std::deque<CClientItem*>::iterator it;
    CClientItem* returnItem = NULL;

    for (it = m_itemList.begin(); it != m_itemList.end(); ++it) {

        CClientItem* pItem = *it;
        if (pItem->getInterfaceGUID() == guid) {
            returnItem = pItem;
            break;
        }
    }

    return returnItem;
}

///////////////////////////////////////////////////////////////////////////////
// getClientFromConnection
//

const CClientItem*
CClientList::getClientFromConnection(const struct mg_connection* pConnection)
{
    std::deque<CClientItem*>::iterator it;
    const CClientItem* returnItem = NULL;

    for (it = m_itemList.begin(); it != m_itemList.end(); ++it) {

        const CClientItem* pItem = *it;
        if (pItem->getConnection() == pConnection) {
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
        str += pItem->getClientItemAsString();
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

    client = pClient->getClientItemAsString();

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// waitEventInMainReceiveQueue
//

bool
CClientList::waitEventInMainReceiveQueue(uint32_t timeoutMs)
{
    int rv;
    if ((-1 == vscp_sem_wait(&m_semSentToAllClients, 10))) {
        if (errno == ETIMEDOUT) {
            return false;
        }
        else {
            spdlog::error("Error waiting for main receive queue semaphore: {}",
                          strerror(errno));
            return false;
        }
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// sendEventToClient
//

bool
CClientList::sendEventToClient(CClientItem* pClientItem, vscpEvent* pEvent)
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

    // Make sure it uses unix nanoseconds timestamp format
    if (VSCP_HEADER16_FRAME_VERSION_ORIGINAL ==
        (pEvent->head & VSCP_HEADER16_FRAME_VERSION_MASK)) {
        // Set head with UNIX_NS frame version
        pEvent->head |= VSCP_HEADER16_FRAME_VERSION_UNIX_NS;

        pEvent->timestamp_ns = vscp_to_unix_ns(pEvent->year,
                                               pEvent->month,
                                               pEvent->day,
                                               pEvent->hour,
                                               pEvent->minute,
                                               pEvent->second,
                                               pEvent->timestamp);
        pEvent->year         = 0xffff;
        pEvent->month        = 0xff;
    }

    // Create a new event
    vscpEvent* pnewvscpEvent;
    if (vscp_newEvent(&pnewvscpEvent)) {

        // Copy in the new event
        if (!vscp_copyEvent(pnewvscpEvent, pEvent)) {
            vscp_deleteEvent_v2(&pnewvscpEvent);
            spdlog::error("sendEventToClient - Failed to copy event");
            return false;
        }

        if (pClientItem->isReceiveLoopActive()) {
            // Wake up the event manager. Sent the event directly to the client.
            if (!mg_wakeup(
                  &pClientItem->getControlObject()->getTcpipSrv().m_mgr,
                  pClientItem->getConnection()->id,
                  &pnewvscpEvent,
                  sizeof(pnewvscpEvent))) {
                vscp_deleteEvent_v2(&pnewvscpEvent);
                spdlog::error(
                  "sendEventToClient - Failed to wake event manager");
                return false;
            }
        }
        else {
            if (!pClientItem->addEventToSendQueue(pnewvscpEvent)) {
                vscp_deleteEvent_v2(&pnewvscpEvent);
                spdlog::info("sendEventToClient - overrun");
                pClientItem->getStatistics().cntOverruns++;
                return false;
            }
        }
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// sendEventToClient
//

bool
CClientList::sendEventToClient(cguid& destguid, vscpEvent* pEvent)
{
    CClientItem* pClientItem;
    std::deque<CClientItem*>::iterator it;

    if (NULL == pEvent) {
        spdlog::error("sendEventToClient - null event");
        return false;
    }

    pthread_mutex_lock(&m_mutexClientItemList);
    for (it = m_itemList.begin(); it != m_itemList.end(); ++it) {
        pClientItem = *it;

        if ((NULL != pClientItem) &&
            (pClientItem->getInterfaceGUID() == destguid)) {
            if (!sendEventToClient(pClientItem, pEvent)) {
                ;
            }
            pthread_mutex_unlock(&m_mutexClientItemList);
            return true;
        }
    }
    pthread_mutex_unlock(&m_mutexClientItemList);

    spdlog::error("sendEventToClient - client with GUID {} not found",
                  destguid.toString().c_str());
    return false;
}

///////////////////////////////////////////////////////////////////////////////
// sendEventAllClients
//

bool
CClientList::sendEventAllClients(vscpEvent* pEvent, uint32_t excludeID)
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
            spdlog::trace("Send event to client [{}] clientid={}",
                          pClientItem->getDeviceName(),
                          pClientItem->getClientID());
            if (!sendEventToClient(pClientItem, pEvent)) {
                spdlog::error(
                  "sendEventAllClients - Failed to send event to client [{}]",
                  pClientItem->getDeviceName());
            }
        }
    }
    pthread_mutex_unlock(&m_mutexClientItemList);

    // Tell main thread that there are work to do
    sem_post(&m_semSentToAllClients);

    return true;
}