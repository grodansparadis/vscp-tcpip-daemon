// deviceList.h: interface for the CDeviceList class.
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
    @file devicelist.h
    @brief Interface for the CDeviceList class.

    This file contains the definition of the CDeviceList class, which
    manages the list of devices in the VSCP daemon.

    @author Ake Hedman and contributors, the VSCP project
    @date 2000-2026
    @version 1.0
    @copyright Copyright (C) 2000-2026 Ake Hedman and contributors, the VSCP
   project
    @license MIT License
*/

#if !defined(_DEVICELIST_H__0ED35EA7_E9E1_41CD_8A98_5EB3369B3194__INCLUDED_)
#define _DEVICELIST_H__0ED35EA7_E9E1_41CD_8A98_5EB3369B3194__INCLUDED_

#include <deque>
#include <string>

#include <pthread.h>
#include <semaphore.h>

#include "canaldlldef.h"
#include "clientlist.h"
#include "devicethread.h"
#include "guid.h"
#include "level2drvdef.h"

#define NO_TRANSLATION 0 // No translation bit set

// Out - translation bit definitions
#define VSCP_DRIVER_OUT_TR_M1_M2F                                              \
    0x01 // Level 1 measurement -> Level II measurement Float
#define VSCP_DRIVER_OUT_TR_M1_M2S                                              \
    0x02 // Level I measurement -> Level II measurement String
#define VSCP_DRIVER_OUT_TR_ALL_L2                                              \
    0x04 // All Level I events to Level I over level II events

// In - translation bit definitions

enum _driver_levels { VSCP_DRIVER_LEVEL1 = 1, VSCP_DRIVER_LEVEL2 };

class CClientItem;
class cguid;
class CControlObject;

///////////////////////////////////////////////////////////////////////////////
// Driver3Process
//

class Driver3Process {

  public:
    Driver3Process();
    ~Driver3Process();

    void OnTerminate(int pid, int status);
};

/*!
    @brief Interface for the Driver3Process class.
*/

/*!
    @brief CDeviceItem class.

    This class represents an individual device item in the VSCP daemon.
    It contains information about the device, its configuration, and
    provides methods to start, pause, resume, and stop the device driver.
    It also maintains the state of the device and handles the interaction with
   the underlying driver. It is a crucial component for managing device
   interactions within the VSCP daemon.
    @note This class is used internally by the CDeviceList class to manage the
   collection of device items.
    @see CDeviceList
    @ingroup DeviceManagement
    @version 1.0
    @copyright Copyright (C) 2000-2026 Ake Hedman and contributors, the VSCP
   project
    @license MIT License
*/

///////////////////////////////////////////////////////////////////////////////
// CDeviceItem
//

class CDeviceItem {

  public:
    /// Constructor
    CDeviceItem();

    /// Destructor
    virtual ~CDeviceItem();

    /*!
        Get driver info as string
        "bEnable,bActive,name,path,param,level,flags,guid,translation"
        @return Driver info
    */
    std::string getAsString(void);

    /*!
        Start driver
        @param Pointer to control object
        @return true on success, false on failure
    */
    bool startDriver(CControlObject* pCtrlObject);

    /*!
        Pause driver
        @return true on success, false on failure
    */
    bool pauseDriver(void);

    /*!
        Resume driver
        @return true on success, false on failure
    */
    bool resumeDriver(void);

    /*!
        Stop driver
        @return true on success, false on failure
    */
    bool stopDriver(void);

    // Getters/setters

    /*!
        @brief Get the driver level.
        @param  None
        @return Driver level as uint8_t.
    */
    uint8_t getLevel(void) const { return m_driverLevel; }

    /*!
        Set the driver level.
        @param level The driver level to set.
        @return void
    */
    void setLevel(uint8_t level) { m_driverLevel = level; }

    /*!
        Get the control object associated with the driver.
        @return Pointer to the control object.
    */
    CControlObject* getControlObject(void) const { return m_pObj; }

    /*!
        Get the client item associated with the driver.
        @return Pointer to the client item.
    */
    CClientItem* getClientItem(void) const { return m_pClientItem; }

    /*!
        Set the client item associated with the driver.
        @param pClientItem Pointer to the client item to set.
        @return void
    */
    void setClientItem(CClientItem* pClientItem) { m_pClientItem = pClientItem; }

    /*!
        Get the open handle for the driver.
        @return Open handle as a long.
    */
    long getOpenHandle(void) const { return m_openHandle; }

    /*!
        Set the open handle for the driver.
        @param handle The open handle to set for the driver.
        @return void
    */
    void setOpenHandle(long handle) { m_openHandle = handle; }

    /*!
        Set the device flags for the driver.
        @param flags The device flags to set for the driver.
        @return void
    */
    void setDeviceFlags(uint32_t flags) { m_DeviceFlags = flags; }
    
    /*!
        Get the device flags for the driver.
        @return Device flags as a uint32_t.
    */
    uint32_t getDeviceFlags(void) const { return m_DeviceFlags; }

    /*!
        Set the translation value of the driver.
        @param translation The translation value to set for the driver.
        @return void
    */
    void setTranslation(uint32_t translation) { m_translation = translation; }

    /*!
        Get the translation value of the driver.
        @return Translation value as a uint32_t.
    */
    uint32_t getTranslation(void) const { return m_translation; }

    /*!
        Get the name of the device.
        @return Device name as a std::string.
    */
    std::string getName(void) const { return m_strName; }

    /*!
        Set the name of the device.
        @param name The name to set for the device.
        @return void
    */
    void setName(const std::string& name) { m_strName = name; }

    /*!
        Get the path of the device driver.
        @return Device driver path as a std::string.
    */
    std::string getPath(void) const { return m_strPath; }

    /*!
        Set the path of the device driver.
        @param path The path to set for the device driver.
        @return void
    */
    void setPath(const std::string& path) { m_strPath = path; }

    /*!
        Get the parameter string for the device.
        @return Device parameter string as a std::string.
    */
    std::string getConfigurationString(void) const { return m_strConfiguration; }

    /*!
        Set the parameter string for the device.
        @param configuration The configuration string to set for the device.
        @return void
    */
    void setConfigurationString(const std::string& configuration) { m_strConfiguration = configuration; }

    /*!
        Get the flags for the device.
        @return Device flags as a uint32_t.
    */
    uint32_t getFlags(void) const { return m_flags; }

    /*!
        Set the flags for the device.
        @param flags The flags to set for the device.
        @return void
    */
    void setFlags(uint32_t flags) { m_flags = flags; }

    /*!
        Get the enable status of the driver.
        @return true if the driver is enabled, false otherwise.
    */
    bool isEnabled(void) const { return m_bEnable; }

    /*!
        Set Enabled status of the driver.
        @param bEnable true to enable the driver, false to disable it.
        @return void
    */
    void setEnabled(bool bEnable) { m_bEnable = bEnable; }

    /*!
        Get the quit status of the driver.
        @return true if the driver is set to quit, false otherwise.
    */
    bool isQuit(void) const { return m_bQuit; }

    /*!
        Set Quit status of the driver.
        @param bQuit true to set the driver to quit, false otherwise.
        @return void
    */
    void setQuit(bool bQuit) { m_bQuit = bQuit; }

    /*!
        Get the active status of the driver.
        @return true if the driver is active, false otherwise.
    */
    bool isActive(void) const { return m_bActive; }

    /*!
        Set Active status of the driver.
        @param bActive true to set the driver as active, false otherwise.
        @return void
    */
    void setActive(bool bActive) { m_bActive = bActive; }

    /*!
        Get the driver interface GUID.
        @return Driver interface GUID as a cguid.
    */
    cguid getInterfaceGUID(void) const { return m_interface_guid; }

    /*!
        Set the driver interface GUID.
        @param guid The GUID to set for the driver interface.
        @return void
    */
    void setInterfaceGUID(const cguid& guid) { m_interface_guid = guid; }

    /*!
        All level II driver must have a GUID
    */
    /*!
        Get the driver GUID.
        @return Driver GUID as a cguid.
    */
    cguid getDriverGuid(void) const { return m_drvGuid; }

    /*!
        Set the driver GUID.
        @param guid The GUID to set for the driver.
        @return void
    */
    void setDriverGuid(const cguid& guid) { m_drvGuid = guid; }

    

    LPFNDLL_CANALOPEN getProcCanalOpen(void) const { return m_proc_CanalOpen; }
    void setProcCanalOpen(LPFNDLL_CANALOPEN proc)
    {
        m_proc_CanalOpen = proc;
    }

    LPFNDLL_CANALCLOSE getProcCanalClose(void) const { return m_proc_CanalClose; }
    void setProcCanalClose(LPFNDLL_CANALCLOSE proc)
    {
        m_proc_CanalClose = proc;
    }

    LPFNDLL_CANALGETLEVEL getProcCanalGetLevel(void) const
    {
        return m_proc_CanalGetLevel;
    }
    void setProcCanalGetLevel(LPFNDLL_CANALGETLEVEL proc)
    {
        m_proc_CanalGetLevel = proc;
    }

    LPFNDLL_CANALSEND getProcCanalSend(void) const { return m_proc_CanalSend; }
    void setProcCanalSend(LPFNDLL_CANALSEND proc) { m_proc_CanalSend = proc; }

    LPFNDLL_CANALRECEIVE getProcCanalReceive(void) const
    {
        return m_proc_CanalReceive;
    }
    void setProcCanalReceive(LPFNDLL_CANALRECEIVE proc)
    {
        m_proc_CanalReceive = proc;
    }

    LPFNDLL_CANALDATAAVAILABLE getProcCanalDataAvailable(void) const
    {
        return m_proc_CanalDataAvailable;
    }
    void setProcCanalDataAvailable(LPFNDLL_CANALDATAAVAILABLE proc)
    {
        m_proc_CanalDataAvailable = proc;
    }

    LPFNDLL_CANALGETSTATUS getProcCanalGetStatus(void) const
    {
        return m_proc_CanalGetStatus;
    }
    void setProcCanalGetStatus(LPFNDLL_CANALGETSTATUS proc)
    {
        m_proc_CanalGetStatus = proc;
    }

    LPFNDLL_CANALGETSTATISTICS getProcCanalGetStatistics(void) const
    {
        return m_proc_CanalGetStatistics;
    }
    void setProcCanalGetStatistics(LPFNDLL_CANALGETSTATISTICS proc)
    {
        m_proc_CanalGetStatistics = proc;
    }

    LPFNDLL_CANALSETFILTER getProcCanalSetFilter(void) const
    {
        return m_proc_CanalSetFilter;
    }
    void setProcCanalSetFilter(LPFNDLL_CANALSETFILTER proc)
    {
        m_proc_CanalSetFilter = proc;
    }

    LPFNDLL_CANALSETMASK getProcCanalSetMask(void) const
    {
        return m_proc_CanalSetMask;
    }
    void setProcCanalSetMask(LPFNDLL_CANALSETMASK proc)
    {
        m_proc_CanalSetMask = proc;
    }

    LPFNDLL_CANALSETBAUDRATE getProcCanalSetBaudrate(void) const
    {
        return m_proc_CanalSetBaudrate;
    }
    void setProcCanalSetBaudrate(LPFNDLL_CANALSETBAUDRATE proc)
    {
        m_proc_CanalSetBaudrate = proc;
    }

    LPFNDLL_CANALGETVERSION getProcCanalGetVersion(void) const
    {
        return m_proc_CanalGetVersion;
    }
    void setProcCanalGetVersion(LPFNDLL_CANALGETVERSION proc)
    {
        m_proc_CanalGetVersion = proc;
    }

    LPFNDLL_CANALGETDLLVERSION getProcCanalGetDllVersion(void) const
    {
        return m_proc_CanalGetDllVersion;
    }
    void setProcCanalGetDllVersion(LPFNDLL_CANALGETDLLVERSION proc)
    {
        m_proc_CanalGetDllVersion = proc;
    }

    LPFNDLL_CANALGETVENDORSTRING getProcCanalGetVendorString(void) const
    {
        return m_proc_CanalGetVendorString;
    }
    void setProcCanalGetVendorString(LPFNDLL_CANALGETVENDORSTRING proc)
    {
        m_proc_CanalGetVendorString = proc;
    }

    LPFNDLL_CANALBLOCKINGSEND getProcCanalBlockingSend(void) const
    {
        return m_proc_CanalBlockingSend;
    }
    void setProcCanalBlockingSend(LPFNDLL_CANALBLOCKINGSEND proc)
    {
        m_proc_CanalBlockingSend = proc;
    }

    LPFNDLL_CANALBLOCKINGRECEIVE getProcCanalBlockingReceive(void) const
    {
        return m_proc_CanalBlockingReceive;
    }
    void setProcCanalBlockingReceive(LPFNDLL_CANALBLOCKINGRECEIVE proc)
    {
        m_proc_CanalBlockingReceive = proc;
    }

    LPFNDLL_CANALGETDRIVERINFO getProcCanalGetDriverInfo(void) const
    {
        return m_proc_CanalGetdriverInfo;
    }
    void setProcCanalGetDriverInfo(LPFNDLL_CANALGETDRIVERINFO proc)
    {
        m_proc_CanalGetdriverInfo = proc;
    }

    LPFNDLL_VSCPOPEN getProcVSCPOpen(void) const { return m_proc_VSCPOpen; }
    void setProcVSCPOpen(LPFNDLL_VSCPOPEN proc) { m_proc_VSCPOpen = proc; }

    LPFNDLL_VSCPCLOSE getProcVSCPClose(void) const { return m_proc_VSCPClose; }
    void setProcVSCPClose(LPFNDLL_VSCPCLOSE proc) { m_proc_VSCPClose = proc; }

    LPFNDLL_VSCPWRITE getProcVSCPWrite(void) const { return m_proc_VSCPWrite; }
    void setProcVSCPWrite(LPFNDLL_VSCPWRITE proc) { m_proc_VSCPWrite = proc; }

    LPFNDLL_VSCPREAD getProcVSCPRead(void) const { return m_proc_VSCPRead; }
    void setProcVSCPRead(LPFNDLL_VSCPREAD proc) { m_proc_VSCPRead = proc; }

    LPFNDLL_VSCPGETVERSION getProcVSCPGetVersion(void) const
    {
        return m_proc_VSCPGetVersion;
    }
    void setProcVSCPGetVersion(LPFNDLL_VSCPGETVERSION proc)
    {
        m_proc_VSCPGetVersion = proc;
    }

    pthread_t getThreadLevel1Receive(void) const { return m_threadLevel1Receive; }
    void setThreadLevel1Receive(pthread_t thread)
    {
        m_threadLevel1Receive = thread;
    }

    pthread_t getThreadLevel1Write(void) const { return m_threadLevel1Write; }
    void setThreadLevel1Write(pthread_t thread) { m_threadLevel1Write = thread; }

    pthread_t getThreadLevel2Receive(void) const { return m_threadLevel2Receive; }
    void setThreadLevel2Receive(pthread_t thread)
    {
        m_threadLevel2Receive = thread;
    }

    pthread_t getThreadLevel2Write(void) const { return m_threadLevel2Write; }
    void setThreadLevel2Write(pthread_t thread) { m_threadLevel2Write = thread; }

  private:
    // Name of device
    std::string m_strName;

    /*!
        Level I:    Device configuration string.
        Level II:   Path to XML/JSON config file.
    */
    std::string m_strConfiguration;

    // Device flags (from config)
    uint32_t m_flags;

    // Driver DLL/DL path
    std::string m_strPath;

    // Canal/VSCP Driver Level
    uint8_t m_driverLevel;

    // True if driver should be started.
    bool m_bEnable;

    // Paused driver is inactive
    bool m_bActive;

    // termination control
    bool m_bQuit;

    /*!
        GUID to use for driver interface if set
        four msb should be zero for this GUID
    */
    cguid m_interface_guid;

    /*!
        All level II driver must have a GUID
    */
    cguid m_drvGuid;

    // Device flags for CANAL DLL open
    uint32_t m_DeviceFlags;

    // Client entry
    CClientItem* m_pClientItem;

    // Mutex handle that is used for sharing of the device.
    pthread_mutex_t m_deviceMutex;

    /*!
     *  Translation flags
     *  High 16-bits incoming.
     *  Low 16-bit outgoing.
     */
    uint32_t m_translation;

    // Handle for dll/dl driver interface
    long m_openHandle;

    // Worker thread for device
    pthread_t m_deviceThreadHandle;
    pthread_mutex_t m_mutexdeviceThread;

    // ------------------------------------------------------------------------
    //                     Start of driver worker thread data
    // ------------------------------------------------------------------------

    // Control object that invoked thread
    CControlObject* m_pObj;

    // Holder for CANAL receive thread
    pthread_t m_threadLevel1Receive;

    // Holder for CANAL write thread
    pthread_t m_threadLevel1Write;

    // Holder for VSCP Level II receive thread
    pthread_t m_threadLevel2Receive;

    // Holder for VSCP Level II write thread
    pthread_t m_threadLevel2Write;

    // ------------------------------------------------------------------------
    //                     End of driver worker thread data
    // ------------------------------------------------------------------------

    // Level I (CANAL) driver methods

    LPFNDLL_CANALOPEN m_proc_CanalOpen;
    LPFNDLL_CANALCLOSE m_proc_CanalClose;
    LPFNDLL_CANALGETLEVEL m_proc_CanalGetLevel;
    LPFNDLL_CANALSEND m_proc_CanalSend;
    LPFNDLL_CANALRECEIVE m_proc_CanalReceive;
    LPFNDLL_CANALDATAAVAILABLE m_proc_CanalDataAvailable;
    LPFNDLL_CANALGETSTATUS m_proc_CanalGetStatus;
    LPFNDLL_CANALGETSTATISTICS m_proc_CanalGetStatistics;
    LPFNDLL_CANALSETFILTER m_proc_CanalSetFilter;
    LPFNDLL_CANALSETMASK m_proc_CanalSetMask;
    LPFNDLL_CANALSETBAUDRATE m_proc_CanalSetBaudrate;
    LPFNDLL_CANALGETVERSION m_proc_CanalGetVersion;
    LPFNDLL_CANALGETDLLVERSION m_proc_CanalGetDllVersion;
    LPFNDLL_CANALGETVENDORSTRING m_proc_CanalGetVendorString;

    // Generation 2
    LPFNDLL_CANALBLOCKINGSEND m_proc_CanalBlockingSend;
    LPFNDLL_CANALBLOCKINGRECEIVE m_proc_CanalBlockingReceive;
    LPFNDLL_CANALGETDRIVERINFO m_proc_CanalGetdriverInfo;

    // Level II driver methods
    LPFNDLL_VSCPOPEN m_proc_VSCPOpen;
    LPFNDLL_VSCPCLOSE m_proc_VSCPClose;
    LPFNDLL_VSCPWRITE m_proc_VSCPWrite;
    LPFNDLL_VSCPREAD m_proc_VSCPRead;
    LPFNDLL_VSCPGETVERSION m_proc_VSCPGetVersion;
};

/*!
    @file devicelist.h
    @brief Interface for the device list in the VSCP daemon.

    This file contains the declaration for the CDeviceList class, which manages
    a collection of device items within the VSCP daemon. It provides methods
    to add, remove, and retrieve device items, as well as to count and list
    all available drivers.

    @author Ake Hedman and contributors, the VSCP project
    @date 2000-2026
    @version 1.0
    @copyright Copyright (C) 2000-2026 Ake Hedman and contributors, the VSCP
   project
    @license MIT License
*/

class CDeviceList {
  public:
    CDeviceList();
    virtual ~CDeviceList();

    /*!
        Add one driver item
        @param strName Driver name
        @param m_strConfiguration Driver configuration string
        @param flags Driver flags
        @param guid Interface GUID
        @param level Mark as Level I or Level II driver
        @param bEnable True to enable driver
        @param translation Bits to set translations to be performed.
        @return True is returned if the driver was successfully added.
    */
    bool addItem(const std::string& strName,
                 const std::string& m_strConfiguration,
                 const std::string& strPath,
                 uint32_t flags,
                 const cguid& guid,
                 uint8_t level        = VSCP_DRIVER_LEVEL1,
                 bool bEnable         = true,
                 uint32_t translation = NO_TRANSLATION);

    /*!
        Remove a driver item
        @param clientid for the driver to remove
        @return True if driver was removed successfully
                otherwise false.
    */
    bool removeItem(unsigned long id);

    /*!
        Get device from it's name
        @param name Name of device.
        @return Pointer to a device item or NULL if not found.
    */
    CDeviceItem* getDeviceItemFromName(std::string& name);
    /*!
        Get device item from GUID
        @param guid for device to look for
        @return Pointer to device item or NULL if not found.
    */
    CDeviceItem* getDeviceItemFromGUID(cguid& guid);

    /*!
        Get device item from the client id
        @param guid for device to look for
        @return Pointer to device item or NULL if not found.
    */
    CDeviceItem* getDeviceItemFromClientId(uint32_t id);

    /*!
        Get all drivers as a string
        @return String with device item info lines separated
        with \r\n
    */
    std::string getAllAsString(void);

    /*!
        Count number of drivers
        @param type Type of driver to count (1/2/3) or all (0)
        @param bOnlyActive True if only enabled drivers should be counted.
        @return number of drivers
    */
    uint16_t getCountDrivers(uint8_t type = 0, bool bOnlyActive = false);

  public:
    /*!
        List with devices
    */
    std::deque<CDeviceItem*> m_devItemList;
};

#endif // !defined(_DEVICELIST_H__0ED35EA7_E9E1_41CD_8A98_5EB3369B3194__INCLUDED_)
