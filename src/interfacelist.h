// interfacelist.h
//
// This file is part of the VSCP (https://www.vscp.org)
//
// Copyright (C) 2000-2026 Ake Hedman and contributors, the VSCP Project
// <info@vscp.org>
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: GPL-2.0-only

/*!
  @file interfacelist.h
  @brief Interface for the CInterfaceList class.

  This file contains the definition of the CInterfaceList class, which
  manages the list of network interfaces in the VSCP daemon.
  The class provides methods to add and retrieve interface items.

  @author Ake Hedman and contributors, the VSCP project
  @date 2000-2026
  @version 1.0
  @copyright Copyright (C) 2000-2026 Ake Hedman and contributors, the VSCP project
  @license MIT License
  */

#if !defined(INTERFACELIST__INCLUDED_)
#define INTERFACELIST__INCLUDED_

#include <guid.h>

class CInterfaceItem
{

  public:
    /// Constructor
    CInterfaceItem(void);

    /// Destructor
    virtual ~CInterfaceItem(void);

    /// IP Address for interface
    std::string m_ipaddress;

    /// MAC address for interface
    std::string m_macaddress;

    /// GUID for interface
    cguid m_guid;

  protected:
    /*!
        System assigned ID for interface
    */
    uint32_t m_interfaceID;
};

class CInterfaceList
{
  public:
    /// Constructor
    CInterfaceList(void);

    /// Destructor
    virtual ~CInterfaceList(void);

    /*!
        Add interface
        @param ip IP address for interface.
        @param mac MAC address for interface.
        @param guid GUID for interface in string form.
        @return true on success, false on failure.
    */
    bool addInterface(const std::string &ip,
                      const std::string &mac,
                      const std::string &guid);

    /*!
        Add interface
        @param ip IP address for interface.
        @param mac MAC address for interface.
        @param guid GUID for interface.
        @return true on success, false on failure.
    */
    bool addInterface(const std::string &ip,
                      const std::string &mac,
                      const cguid &guid);

  protected:
    /*!
        List with interface items
    */
    std::deque<CInterfaceItem *> m_tcpclientlist;
};

#endif
