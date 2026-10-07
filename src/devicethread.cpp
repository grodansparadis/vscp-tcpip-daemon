// devicethread.cpp
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

#define _POSIX

#include <dlfcn.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#ifndef WIN32
#include <sys/wait.h>
#endif
#include <syslog.h>
#include <unistd.h>

#ifndef DWORD
#define DWORD unsigned long
#endif

#include "spdlog/spdlog.h"

#include "controlobject.h"

// #include <dllist.h>
#include <canal-macro.h>
#include <level2drvdef.h>
#include <vscp.h>
#include <vscphelper.h>

#include "devicethread.h"

///////////////////////////////////////////////////////////////////////////////
// deviceThread
//

void*
deviceThread(void* pdata)
{
    CDeviceItem* pDevItem = (CDeviceItem*)pdata;
    if (NULL == pDevItem) {
        spdlog::error("No device item defined. Aborting device thread!");
        return NULL;
    }

    // Must have a valid pointer to the control object
    CControlObject* pObj = pDevItem->getControlObject();
    if (NULL == pObj) {
        spdlog::error("No control object defined. Aborting device thread!");
        return NULL;
    }

    // We need to create a clientitem and add this object to the list
    CClientItem* pClientItem = new CClientItem;
    if (NULL == pClientItem) {
        return NULL;
    }
    pDevItem->setClientItem(pClientItem);

    // This is now an active Client
    pClientItem->setOpen(true);
    if (VSCP_DRIVER_LEVEL1 == pDevItem->getLevel()) {
        pClientItem->setInterfaceType(
          CClientItem::CLIENT_ITEM_INTERFACE_TYPE_DRIVER_LEVEL1);
    }
    else if (VSCP_DRIVER_LEVEL2 == pDevItem->getLevel()) {
        pClientItem->setInterfaceType(
          CClientItem::CLIENT_ITEM_INTERFACE_TYPE_DRIVER_LEVEL2);
    }

    pClientItem->setDateTimeStartedNow();
    pClientItem->setDeviceName("driver_" + pDevItem->getName());

    spdlog::debug("Devicethread: Starting {}",
                  pClientItem->getDeviceName().c_str());

    // Add the client to the Client List
    cguid guid = pDevItem->getInterfaceGUID();
    if (!pObj->addClient(pClientItem, guid)) {
        // Failed to add client
        delete pDevItem->getClientItem();
        pDevItem->setClientItem(NULL);
        spdlog::error(
          "Devicethread: Failed to add client. Terminating thread.");
        return NULL;
    }

    // Client now have GUID set to the server GUID + channel id
    // If the device has a non NULL GUID, replace the client GUID with
    // the device GUID  preserving the channel id
    if (!pDevItem->getInterfaceGUID().isNULL()) {
        uint16_t clinetid = pClientItem->getInterfaceGUID().getClientID();
        pClientItem->setInterfaceGUID(pDevItem->getInterfaceGUID());
        pClientItem->getInterfaceGUID().setClientID(clinetid);
    }

    void* hdll; // dl/dll handle

    // Load dynamic library
    hdll = dlopen(pDevItem->getPath().c_str(), RTLD_LAZY);
    if (!hdll) {
        spdlog::error("Devicethread: Unable to load dynamic library. path = %s",
                      pDevItem->getPath().c_str());
        return NULL;
    }

    //*************************************************************************
    //                         Level I drivers
    //*************************************************************************
    if (VSCP_DRIVER_LEVEL1 == pDevItem->getLevel()) {

        // Now find methods in library

        spdlog::debug("Loading level I driver: %s",
                      pDevItem->getName().c_str());

        // * * * * CANAL OPEN * * * *
        pDevItem->setProcCanalOpen(
          (LPFNDLL_CANALOPEN)dlsym(hdll, "CanalOpen"));
        const char* dlsym_error = dlerror();

        if (dlsym_error) {
            // Free the library
            spdlog::error("%s : Unable to get dl entry for CanalOpen.",
                          pDevItem->getName().c_str());
            return NULL;
        }

        // * * * * CANAL CLOSE * * * *
        pDevItem->setProcCanalClose(
          (LPFNDLL_CANALCLOSE)dlsym(hdll, "CanalClose"));
        dlsym_error = dlerror();
        if (dlsym_error) {
            // Free the library
            spdlog::error("%s: Unable to get dl entry for CanalClose.",
                          pDevItem->getName().c_str());
            dlclose(hdll);
            return NULL;
        }

        // * * * * CANAL GETLEVEL * * * *
        pDevItem->setProcCanalGetLevel(
          (LPFNDLL_CANALGETLEVEL)dlsym(hdll, "CanalGetLevel"));
        dlsym_error = dlerror();
        if (dlsym_error) {
            // Free the library
            spdlog::error("%s: Unable to get dl entry for CanalGetLevel.",
                          pDevItem->getName().c_str());
            dlclose(hdll);
            return NULL;
        }

        // * * * * CANAL SEND * * * *
        pDevItem->setProcCanalSend(
          (LPFNDLL_CANALSEND)dlsym(hdll, "CanalSend"));
        dlsym_error = dlerror();
        if (dlsym_error) {
            // Free the library
            spdlog::error("%s: Unable to get dl entry for CanalSend.",
                          pDevItem->getName().c_str());
            dlclose(hdll);
            return NULL;
        }

        // * * * * CANAL DATA AVAILABLE * * * *
        pDevItem->setProcCanalDataAvailable(
          (LPFNDLL_CANALDATAAVAILABLE)dlsym(hdll, "CanalDataAvailable"));
        dlsym_error = dlerror();
        if (dlsym_error) {
            // Free the library
            spdlog::error("%s: Unable to get dl entry for CanalDataAvailable.",
                          pDevItem->getName().c_str());
            dlclose(hdll);
            return NULL;
        }

        // * * * * CANAL RECEIVE * * * *
        pDevItem->setProcCanalReceive(
          (LPFNDLL_CANALRECEIVE)dlsym(hdll, "CanalReceive"));
        dlsym_error = dlerror();
        if (dlsym_error) {
            // Free the library
            spdlog::error("%s: Unable to get dl entry for CanalReceive.",
                          pDevItem->getName().c_str());
            dlclose(hdll);
            return NULL;
        }

        // * * * * CANAL GET STATUS * * * *
        pDevItem->setProcCanalGetStatus(
          (LPFNDLL_CANALGETSTATUS)dlsym(hdll, "CanalGetStatus"));
        dlsym_error = dlerror();
        if (dlsym_error) {
            // Free the library
            spdlog::error("%s: Unable to get dl entry for CanalGetStatus.",
                          pDevItem->getName().c_str());
            dlclose(hdll);
            return NULL;
        }

        // * * * * CANAL GET STATISTICS * * * *
        pDevItem->setProcCanalGetStatistics(
          (LPFNDLL_CANALGETSTATISTICS)dlsym(hdll, "CanalGetStatistics"));
        dlsym_error = dlerror();
        if (dlsym_error) {
            // Free the library
            spdlog::error("%s: Unable to get dl entry for CanalGetStatistics.",
                          pDevItem->getName().c_str());
            dlclose(hdll);
            return NULL;
        }

        // * * * * CANAL SET FILTER * * * *
        pDevItem->setProcCanalSetFilter(
          (LPFNDLL_CANALSETFILTER)dlsym(hdll, "CanalSetFilter"));
        dlsym_error = dlerror();
        if (dlsym_error) {
            // Free the library
            spdlog::error("%s: Unable to get dl entry for CanalSetFilter.",
                          pDevItem->getName().c_str());
            dlclose(hdll);
            return NULL;
        }

        // * * * * CANAL SET MASK * * * *
        pDevItem->setProcCanalSetMask(
          (LPFNDLL_CANALSETMASK)dlsym(hdll, "CanalSetMask"));
        dlsym_error = dlerror();
        if (dlsym_error) {
            // Free the library
            spdlog::error("%s: Unable to get dl entry for CanalSetMask.",
                          pDevItem->getName().c_str());
            dlclose(hdll);
            return NULL;
        }

        // * * * * CANAL GET VERSION * * * *
        pDevItem->setProcCanalGetVersion(
          (LPFNDLL_CANALGETVERSION)dlsym(hdll, "CanalGetVersion"));
        dlsym_error = dlerror();
        if (dlsym_error) {
            // Free the library
            spdlog::error("%s: Unable to get dl entry for CanalGetVersion.",
                          pDevItem->getName().c_str());
            dlclose(hdll);
            return NULL;
        }

        // * * * * CANAL GET DLL VERSION * * * *
        pDevItem->setProcCanalGetDllVersion(
          (LPFNDLL_CANALGETDLLVERSION)dlsym(hdll, "CanalGetDllVersion"));
        dlsym_error = dlerror();
        if (dlsym_error) {
            // Free the library
            spdlog::error("%s: Unable to get dl entry for CanalGetDllVersion.",
                          pDevItem->getName().c_str());
            dlclose(hdll);
            return NULL;
        }

        // * * * * CANAL GET VENDOR STRING * * * *
        pDevItem->setProcCanalGetVendorString(
          (LPFNDLL_CANALGETVENDORSTRING)dlsym(hdll, "CanalGetVendorString"));
        dlsym_error = dlerror();
        if (dlsym_error) {
            // Free the library
            spdlog::error(
              "%s: Unable to get dl entry for CanalGetVendorString.",
              pDevItem->getName().c_str());
            dlclose(hdll);
            return NULL;
        }

        // ******************************
        //     Generation 2 Methods
        // ******************************

        // * * * * CANAL BLOCKING SEND * * * *
        pDevItem->setProcCanalBlockingSend(
          (LPFNDLL_CANALBLOCKINGSEND)dlsym(hdll, "CanalBlockingSend"));
        dlsym_error = dlerror();
        if (dlsym_error) {
            spdlog::error(
              "%s: Unable to get dl entry for CanalBlockingSend. Probably "
              "Generation 1 driver.",
              pDevItem->getName().c_str());
            pDevItem->setProcCanalBlockingSend(nullptr);
        }

        // * * * * CANAL BLOCKING RECEIVE * * * *
        pDevItem->setProcCanalBlockingReceive(
          (LPFNDLL_CANALBLOCKINGRECEIVE)dlsym(hdll, "CanalBlockingReceive"));
        dlsym_error = dlerror();
        if (dlsym_error) {
            spdlog::error(
              "%s: Unable to get dl entry for CanalBlockingReceive. "
              "Probably Generation 1 driver.",
              pDevItem->getName().c_str());
            pDevItem->setProcCanalBlockingReceive(nullptr);
        }

        // * * * * CANAL GET DRIVER INFO * * * *
        pDevItem->setProcCanalGetDriverInfo(
          (LPFNDLL_CANALGETDRIVERINFO)dlsym(hdll, "CanalGetDriverInfo"));
        dlsym_error = dlerror();
        if (dlsym_error) {
            spdlog::error("%s: Unable to get dl entry for CanalGetDriverInfo. "
                          "Probably Generation 1 driver.",
                          pDevItem->getName().c_str());
            pDevItem->setProcCanalGetDriverInfo(nullptr);
        }

        // Open the device
        pDevItem->setOpenHandle(pDevItem->getProcCanalOpen()(
          pDevItem->getConfigurationString().c_str(),
          pDevItem->getDeviceFlags()));

        // Check if the driver opened properly
        if (pDevItem->getOpenHandle() <= 0) {
            spdlog::error("Failed to open driver. Will not use it! %ld [%s] ",
                          pDevItem->getOpenHandle(),
                          pDevItem->getName().c_str());
            dlclose(hdll);
            return NULL;
        }

        spdlog::debug("%s: [Device tread] Level I Driver open.",
                      pDevItem->getName().c_str());

        // Get Driver Level
        pDevItem->setLevel(
          pDevItem->getProcCanalGetLevel()(pDevItem->getOpenHandle()));

        //  * * * Level I Driver * * *

        // Check if blocking driver is available
        if (NULL != pDevItem->getProcCanalBlockingReceive()) {

            // * * * * Blocking version * * * *

            spdlog::debug("%s: [Device tread] Level I blocking version.",
                          pDevItem->getName().c_str());

            /////////////////////////////////////////////////////////////////////////////
            //                      Device write worker thread
            /////////////////////////////////////////////////////////////////////////////

            pthread_t threadLevel1Write;
            if (pthread_create(&threadLevel1Write,
                               NULL,
                               deviceLevel1WriteThread,
                               pDevItem)) {
                spdlog::error(
                  "%s: Unable to run the device write worker thread.",
                  pDevItem->getName().c_str());
                dlclose(hdll);
                return NULL;
            }
            pDevItem->setThreadLevel1Write(threadLevel1Write);

            /////////////////////////////////////////////////////////////////////////////
            // Device read worker thread
            /////////////////////////////////////////////////////////////////////////////
            pthread_t threadLevel1Receive;
            if (pthread_create(&threadLevel1Receive,
                               NULL,
                               deviceLevel1ReceiveThread,
                               pDevItem)) {
                spdlog::error(
                  "%s: Unable to run the device read worker thread.",
                  pDevItem->getName().c_str());
                pDevItem->setQuit(true);
                pthread_join(pDevItem->getThreadLevel1Write(), NULL);
                dlclose(hdll);
                return NULL;
            }
            pDevItem->setThreadLevel1Receive(threadLevel1Receive);

            // Just sit and wait until the end of the world as we know it...
            while (!pDevItem->isQuit()) {
                sleep(1);
            }

            // Signal worker threads to quit
            pDevItem->setQuit(true);

            spdlog::debug("%s: [Device tread] Level I work loop ended.",
                          pDevItem->getName().c_str());

            // Wait for workerthreads to abort
            pthread_join(pDevItem->getThreadLevel1Write(), NULL);
            pthread_join(pDevItem->getThreadLevel1Receive(), NULL);
        }
        else {

            // * * * * Non blocking version * * * *

            spdlog::debug("%s: [Device tread] Level I NON Blocking version.",
                          pDevItem->getName().c_str());

            bool bActivity;
            while (!pDevItem->isQuit()) {

                bActivity = false;
                /////////////////////////////////////////////////////////////////////////////
                //                           Receive from device
                /////////////////////////////////////////////////////////////////////////////
                canalMsg msg;
                if (pDevItem->getProcCanalDataAvailable()(
                      pDevItem->getOpenHandle())) {

                    if (CANAL_ERROR_SUCCESS ==
                        pDevItem->getProcCanalReceive()(pDevItem->getOpenHandle(),
                                                         &msg)) {

                        bActivity = true;

                        // There must be room in the receive queue
                        if (pObj->getMaxItemsInClientReceiveQueue() >
                            pObj->getClientList().getOutputQueueSize()) {

                            vscpEvent* pev = new vscpEvent;
                            if (NULL != pev) {

                                // Set driver GUID if set
                                if (pDevItem->getInterfaceGUID().isNULL()) {
                                    pDevItem->getInterfaceGUID().writeGUID(
                                      pev->GUID);
                                }
                                else {
                                    // If no driver GUID set use interface GUID
                                    pClientItem->getInterfaceGUID().writeGUID(
                                      pev->GUID);
                                }

                                // Convert CANAL message to VSCP event
                                vscp_convertCanalToEvent(
                                  pev,
                                  &msg,
                                  (unsigned char *)pClientItem->getInterfaceGUID().getGUID());

                                pev->obid = pClientItem->getClientID();

                                if (!pObj->getClientList().enqueueReceiveEvent(
                                      pev,
                                      pObj->getMaxItemsInClientReceiveQueue())) {
                                    vscp_deleteEvent_v2(&pev);
                                }
                            }
                        }
                    }
                } // data available

                // * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
                //          Send messages (if any) in the output queue
                // * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *

                vscpEvent* pev =
                  pClientItem->getEventFromClientInputQueue(false);
                if (NULL != pev) {
                    bActivity = true;

                    // Trow away Level II event on Level I interface
                    if ((CClientItem::
                           CLIENT_ITEM_INTERFACE_TYPE_DRIVER_LEVEL1 ==
                         pClientItem->getInterfaceType()) &&
                        (pev->vscp_class > 512)) {
                        // Remove the event and the node
                        vscpEvent* pRemovedEvent =
                          pClientItem->getEventFromClientInputQueue(true);
                        spdlog::error(
                          "Level II event on Level I queue thrown away. "
                          "class=%d, type=%d",
                          pev->vscp_class,
                          pev->vscp_type);
                        vscp_deleteEvent(pRemovedEvent);
                        continue;
                    }

                    canalMsg canmsg;
                    vscp_convertEventToCanal(&canmsg, pev);
                    if (CANAL_ERROR_SUCCESS ==
                        pDevItem->getProcCanalSend()(pDevItem->getOpenHandle(),
                                                      &canmsg)) {
                        // Remove the event and the node
                        vscpEvent* pRemovedEvent =
                          pClientItem->getEventFromClientInputQueue(true);
                        vscp_deleteEvent(pRemovedEvent);
                    }
                    else {
                        // Another try
                        // pObj->m_semClientOutputQueue.Post();
                    }

                } // events

                if (!bActivity) {
                    usleep(100000); // 100 ms
                }

                bActivity = false;

            } // while working - non blocking

        } // if blocking/non blocking

        spdlog::debug("%s: [Device tread] Level I Work loop ended.",
                      pDevItem->getName().c_str());

        // Close CANAL channel
        pDevItem->getProcCanalClose()(pDevItem->getOpenHandle());

        spdlog::debug("%s: [Device tread] Level I Closed.",
                      pDevItem->getName().c_str());

        pDevItem->setQuit(true);
        pthread_join(pDevItem->getThreadLevel1Write(), NULL);
        pthread_join(pDevItem->getThreadLevel1Receive(), NULL);

        dlclose(hdll);
    }

    //*************************************************************************
    //                         Level II drivers
    //*************************************************************************

    else if (VSCP_DRIVER_LEVEL2 == pDevItem->getLevel()) {

        // Now find methods in library
        spdlog::info("Loading level II driver: <%s>",
                     pDevItem->getName().c_str());

        // * * * * VSCP OPEN * * * *
        pDevItem->setProcVSCPOpen(
          (LPFNDLL_VSCPOPEN)dlsym(hdll, "VSCPOpen"));
        if (NULL == pDevItem->getProcVSCPOpen()) {
            // Free the library
            spdlog::error("%s: Unable to get dl entry for VSCPOpen.",
                          pDevItem->getName().c_str());
            return NULL;
        }

        // * * * * VSCP CLOSE * * * *
        pDevItem->setProcVSCPClose(
          (LPFNDLL_VSCPCLOSE)dlsym(hdll, "VSCPClose"));
        if (NULL == pDevItem->getProcVSCPClose()) {
            // Free the library
            spdlog::error("%s: Unable to get dl entry for VSCPClose.",
                          pDevItem->getName().c_str());
            return NULL;
        }

        // * * * * VSCPWRITE * * * *
        pDevItem->setProcVSCPWrite(
          (LPFNDLL_VSCPWRITE)dlsym(hdll, "VSCPWrite"));
        if (NULL == pDevItem->getProcVSCPWrite()) {
            // Free the library
            spdlog::error("%s: Unable to get dl entry for VSCPWrite.",
                          pDevItem->getName().c_str());
            return NULL;
        }

        // * * * * VSCPREAD * * * *
        pDevItem->setProcVSCPRead(
          (LPFNDLL_VSCPREAD)dlsym(hdll, "VSCPRead"));
        if (NULL == pDevItem->getProcVSCPRead()) {
            // Free the library
            spdlog::error("%s: Unable to get dl entry for VSCPBlockingReceive.",
                          pDevItem->getName().c_str());
            return NULL;
        }

        // * * * * VSCP GET VERSION * * * *
        pDevItem->setProcVSCPGetVersion(
          (LPFNDLL_VSCPGETVERSION)dlsym(hdll, "VSCPGetVersion"));
        if (NULL == pDevItem->getProcVSCPGetVersion()) {
            // Free the library
            spdlog::error("%s: Unable to get dl entry for VSCPGetVersion.",
                          pDevItem->getName().c_str());
            return NULL;
        }

        spdlog::debug("%s: Discovered all methods\n",
                      pDevItem->getName().c_str());

        // Open up the driver
        pDevItem->setOpenHandle(
          pDevItem->getProcVSCPOpen()(
            pDevItem->getConfigurationString().c_str(),
            pDevItem->getDriverGuid().getGUID()));

        if (0 == pDevItem->getOpenHandle()) {
            // Free the library
            spdlog::error(
              "%s: [Device tread] Unable to open VSCP "
              " level II driver (path, config file access rights)."
              " There may be additional info from driver "
              "in syslog. If not enable debug flag in drivers config file",
              pDevItem->getName().c_str());
            return NULL;
        }

        spdlog::debug("%s: [Device tread] Level II Open.",
                      pDevItem->getName().c_str());

        /////////////////////////////////////////////////////////////////////////////
        // Level II - Device write worker thread
        /////////////////////////////////////////////////////////////////////////////

        pthread_t threadLevel2Write;
        if (pthread_create(&threadLevel2Write,
                           NULL,
                           deviceLevel2WriteThread,
                           pDevItem)) {
            spdlog::error(
              "%s: Unable to run the device Level II write worker thread.",
              pDevItem->getName().c_str());
            dlclose(hdll);
            return NULL; // TODO close dll
        }
        pDevItem->setThreadLevel2Write(threadLevel2Write);

        spdlog::debug("%s: [Device tread] Level II Write thread created.",
                      pDevItem->getName().c_str());

        /////////////////////////////////////////////////////////////////////////////
        // Level II - Device read worker thread
        /////////////////////////////////////////////////////////////////////////////

        pthread_t threadLevel2Receive;
        if (pthread_create(&threadLevel2Receive,
                           NULL,
                           deviceLevel2ReceiveThread,
                           pDevItem)) {
            spdlog::error(
              "%s: Unable to run the device Level II read worker thread.",
              pDevItem->getName().c_str());
            pDevItem->setQuit(true);
            pthread_join(pDevItem->getThreadLevel2Write(), NULL);
            dlclose(hdll);
            return NULL; // TODO close dll, kill other thread
        }
        pDevItem->setThreadLevel2Receive(threadLevel2Receive);

        spdlog::debug("%s: [Device tread] Level II Read thread created.",
                      pDevItem->getName().c_str());

        // Just sit and wait until the end of the world as we know it...
        while (!pDevItem->isQuit()) {
            sleep(1);
        }

        spdlog::debug("%s: [Device tread] Level II Closing.",
                      pDevItem->getName().c_str());

        // Close channel
        pDevItem->getProcVSCPClose()(pDevItem->getOpenHandle());

        spdlog::debug("%s: [Device tread] Level II Closed.",
                      pDevItem->getName().c_str());

        pDevItem->setQuit(true);
        pthread_join(pDevItem->getThreadLevel2Write(), NULL);
        pthread_join(pDevItem->getThreadLevel2Receive(), NULL);

        // Unload dll
        dlclose(hdll);

        spdlog::debug("%s: [Device tread] Level II Done waiting for threads.",
                      pDevItem->getName().c_str());
    }

    // Remove messages in the client queues
    pObj->getClientList().removeClient(pClientItem);
    // pthread_mutex_lock(&pObj->m_clientList.m_mutexClientItemList);
    // pObj->removeClient(pClientItem);
    // pthread_mutex_unlock(&pObj->m_clientList.m_mutexClientItemList);

    return NULL;
}

// ****************************************************************************

///////////////////////////////////////////////////////////////////////////////
// deviceLevel1ReceiveThread
//

void*
deviceLevel1ReceiveThread(void* pData)
{
    canalMsg msg;
    // Level1MsgOutList::compatibility_iterator nodeLevel1;

    CDeviceItem* pDevItem = (CDeviceItem*)pData;
    if (NULL == pDevItem) {
        SYSLOG(
          LOG_ERR,
          "deviceLevel1ReceiveThread quitting due to NULL DevItem object.");
        return NULL;
    }

    // Blocking receive method must have been found
    if (NULL == pDevItem->getProcCanalBlockingReceive()) {
        return NULL;
    }

    while (!pDevItem->isQuit()) {

        if (CANAL_ERROR_SUCCESS ==
            pDevItem->getProcCanalBlockingReceive()(pDevItem->getOpenHandle(),
                                                    &msg,
                                                    500)) {

            // There must be room in the receive queue
            if (pDevItem->getControlObject()
                  ->getMaxItemsInClientReceiveQueue() >
                pDevItem->getControlObject()->getClientList()
                  .getOutputQueueSize()) {

                vscpEvent* pvscpEvent = new vscpEvent;
                if (NULL != pvscpEvent) {

                    memset(pvscpEvent, 0, sizeof(vscpEvent));

                    // Set driver GUID if set
                    /*if ( pDevItem->m_interface_guid.isNULL()
                    ) { pDevItem->m_interface_guid.writeGUID(
                    pvscpEvent->GUID );
                    }
                    else {
                        // If no driver GUID set use interface GUID
                        pDevItem->m_guid.writeGUID(
                    pvscpEvent->GUID );
                    }*/

                    // Convert CANAL message to VSCP event
                    vscp_convertCanalToEvent(
                      pvscpEvent,
                      &msg,
                      (unsigned char *)pDevItem->getClientItem()->getInterfaceGUID().getGUID());

                    pvscpEvent->obid = pDevItem->getClientItem()->getClientID();

                    // If no GUID is set,
                    //      - Set driver GUID if it is defined
                    //      - Set to interface GUID if not.

                    cguid ifguid;

                    // Save nickname
                    uint8_t nickname_lsb = pvscpEvent->GUID[15];

                    // Set if to use
                    ifguid.writeGUID(pvscpEvent->GUID);
                    ifguid.setAt(14, 0);
                    ifguid.setAt(15, 0);

                    // If if is set to zero use interface id
                    if (vscp_isGUIDEmpty(ifguid.getGUID())) {

                        // Set driver GUID if set
                        if (!pDevItem->getInterfaceGUID().isNULL()) {
                            pDevItem->getInterfaceGUID() = ifguid;
                        }
                        else {
                            // If no driver GUID set use interface GUID
                            pDevItem->getClientItem()->getInterfaceGUID() = cguid(pvscpEvent->GUID);
                        }

                        // Preserve nickname
                        pvscpEvent->GUID[15] = nickname_lsb;
                    }

                    // =========================================================
                    //                   Outgoing translations
                    // =========================================================

                    // Level I measurement events to Level II measurement float
                    if (pDevItem->getTranslation() &
                        VSCP_DRIVER_OUT_TR_M1_M2F) {
                        vscp_convertLevel1MeasurementToLevel2Double(pvscpEvent);
                    }

                    // Level I measurement events to Level II measurement string
                    if (pDevItem->getTranslation() &
                        VSCP_DRIVER_OUT_TR_M1_M2S) {
                        vscp_convertLevel1MeasurementToLevel2String(pvscpEvent);
                    }

                    // Level I events to Level I over Level II events
                    if (pDevItem->getTranslation() &
                        VSCP_DRIVER_OUT_TR_ALL_L2) {
                        pvscpEvent->vscp_class += 512;
                        uint8_t* p = new uint8_t[16 + pvscpEvent->sizeData];
                        if (NULL != p) {
                            memset(p, 0, 16 + pvscpEvent->sizeData);
                            memcpy(p + 16,
                                   pvscpEvent->pdata,
                                   pvscpEvent->sizeData);
                            pvscpEvent->sizeData += 16;
                            delete[] pvscpEvent->pdata;
                            pvscpEvent->pdata = p;
                        }
                    }

                    if (!pDevItem->getControlObject()
                           ->getClientList()
                           .enqueueReceiveEvent(
                          pvscpEvent,
                          pDevItem->getControlObject()
                            ->getMaxItemsInClientReceiveQueue())) {
                        vscp_deleteEvent_v2(&pvscpEvent);
                    }
                }
            }
        }
    }

    return NULL;
}

// ****************************************************************************

///////////////////////////////////////////////////////////////////////////////
// deviceLevel1WriteThread
//

void*
deviceLevel1WriteThread(void* pData)
{
    // Level1MsgOutList::compatibility_iterator nodeLevel1;

    CDeviceItem* pDevItem = (CDeviceItem*)pData;
    if (NULL == pDevItem) {
        spdlog::error(
          "deviceLevel1WriteThread quitting due to NULL DevItem object.");
        return NULL;
    }

    // Blocking send method must have been found
    if (NULL == pDevItem->getProcCanalBlockingSend())
        return NULL;

    while (!pDevItem->isQuit()) {

        // Wait until there is something to send
        CClientItem* pClientItem = pDevItem->getClientItem();
        if ((-1 == pClientItem->waitForInputQueueEvent(500)) &&
            errno == ETIMEDOUT) {
            continue;
        }

        vscpEvent* pev = pClientItem->getEventFromClientInputQueue(true);
        if (NULL != pev) {

            // Trow away event if Level II and Level I interface
            if ((CClientItem::CLIENT_ITEM_INTERFACE_TYPE_DRIVER_LEVEL1 ==
                 pClientItem->getInterfaceType()) &&
                (pev->vscp_class > 512)) {
                vscp_deleteEvent(pev);
                continue;
            }

            canalMsg msg;
            if (!vscp_convertEventToCanal(&msg, pev)) {
                SYSLOG(
                  LOG_ERR,
                  "deviceLevel1WriteThread - vscp_convertEventToCanal failed");
                vscp_deleteEvent(pev);
            }

            if (CANAL_ERROR_SUCCESS ==
                pDevItem->getProcCanalBlockingSend()(pDevItem->getOpenHandle(),
                                                     &msg,
                                                     300)) {
                SYSLOG(
                  LOG_ERR,
                  "deviceLevel1WriteThread - m_proc_CanalBlockingSend failed");
                vscp_deleteEvent(pev);
            }
            else {
                // Give it another try
                pDevItem->getControlObject()
                  ->getClientList()
                  .notifyOutputQueueEvent();
            }

        } // events in queue

    } // while

    return NULL;
}

//-----------------------------------------------------------------------------
//                               L e v e l  I I
//-----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// deviceLevel2ReceiveThread
//
//  Read from device
//

void*
deviceLevel2ReceiveThread(void* pData)
{
    vscpEvent* pev;

    CDeviceItem* pDevItem = (CDeviceItem*)pData;
    if (NULL == pDevItem) {
        SYSLOG(
          LOG_ERR,
          "deviceLevel2ReceiveThread quitting due to NULL DevItem object.");
        return NULL;
    }

    int rv;
    while (!pDevItem->isQuit()) {

        pev = new vscpEvent;
        if (NULL == pev)
            continue;
        rv = pDevItem->getProcVSCPRead()(pDevItem->getOpenHandle(), pev, 500);

        if ((CANAL_ERROR_SUCCESS != rv) || (NULL == pev)) {
            delete pev;
            continue;
        }

        // Identify ourselves
        pev->obid = pDevItem->getClientItem()->getClientID();

        // If timestamp is zero we set it here
        if (0 == pev->timestamp) {
            pev->timestamp = vscp_makeTimeStamp();
        }

        // If no GUID is set,
        //      - Set driver GUID if define
        //      - Set interface GUID if no driver GUID defined.

        uint8_t ifguid[16];

        // Save nickname
        uint8_t nickname_msb = pev->GUID[14];
        uint8_t nickname_lsb = pev->GUID[15];

        // Set if to use
        memcpy(ifguid, pev->GUID, 16);
        ifguid[14] = 0;
        ifguid[15] = 0;

        // If if is set to zero use interface id
        if (vscp_isGUIDEmpty(ifguid)) {

            // Set driver GUID if set
            if (!pDevItem->getInterfaceGUID().isNULL()) {
                pDevItem->getInterfaceGUID().writeGUID(pev->GUID);
            }
            else {
                // If no driver GUID set use interface GUID
                pDevItem->getClientItem()->getInterfaceGUID().writeGUID(
                  pev->GUID);
            }

            // Preserve nickname
            pev->GUID[14] = nickname_msb;
            pev->GUID[15] = nickname_lsb;
        }

        // There must be room in the receive queue
        if (!pDevItem->getControlObject()->getClientList().enqueueReceiveEvent(
              pev,
              pDevItem->getControlObject()->getMaxItemsInClientReceiveQueue())) {
            vscp_deleteEvent_v2(&pev);
        }
    }

    return NULL;
}

// ****************************************************************************

///////////////////////////////////////////////////////////////////////////////
// deviceLevel2WriteThread
//
//  Write to device
//

void*
deviceLevel2WriteThread(void* pData)
{
    CDeviceItem* pDevItem = (CDeviceItem*)pData;
    if (NULL == pDevItem) {
        spdlog::error(
          "deviceLevel2WriteThread quitting due to NULL DevItem object.");
        return NULL;
    }

    CClientItem* pClientItem = pDevItem->getClientItem();

    while (!pDevItem->isQuit()) {

        // Wait until there is something to send
        if ((-1 == pClientItem->waitForInputQueueEvent(500)) &&
            errno == ETIMEDOUT) {
            continue;
        }

        vscpEvent* pev = pClientItem->getEventFromClientInputQueue(false);
        if (NULL != pev) {
            if (CANAL_ERROR_SUCCESS ==
                pDevItem->getProcVSCPWrite()(pDevItem->getOpenHandle(), pev, 300)) {

                pClientItem->getEventFromClientInputQueue(true);
            }
            else {
                // Give it another try
                pDevItem->getControlObject()
                  ->getClientList()
                  .notifyOutputQueueEvent();
            }

        } // events in queue

    } // while

    return NULL;
}
