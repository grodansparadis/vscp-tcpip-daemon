// DeviceList.h: interface for the CDeviceList class.
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
//

#if !defined(_DEVICEITEM_H__0ED35EA7_E9E3_41CD_8A98_5EB3369B3194__INCLUDED_)
#define _DEVICEITEM_H__0ED35EA7_E9E3_41CD_8A98_5EB3369B3194__INCLUDED_

#ifdef WIN32
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#endif

#include "vscp.h"

/*!
  * * * Used by CCanalSuperWrapper * * *

  Structure for registry and config file
  interaction with device parameters
*/


typedef struct _devItem
{
    int id;
    int regid;
    std::string strName;       // Name of device
    std::string strPath;       // Path to device
    std::string strParameters; // Configuration parameters for device
    std::string strPrefix;     // Level II/III driver prefix for device flags
    std::string strPathConfig; // Path to config file for Level II/III
    uint32_t flags;            // Bit flags for device
    uint32_t filter;           // Incoming filter for level I device
    uint32_t mask;             // Incoming mask for level I device
    std::string strUsername;   // Level III username for device driver
    std::string strPassword;   // Level III password for device driver
    short port;                // Level III port for device driver

    // Constructs a device item
    _devItem() :
        id(0),
        regid(0),
        strName(),
        strPath(),
        strParameters(),
        strPathConfig(),
        strPrefix(),
        flags(0),
        filter(0),
        mask(0),
        strUsername(),
        strPassword(),
        port(0)
    {
    }

    // Copy constructer for device item
    _devItem(const _devItem& item) :
        id(item.id),
        regid(item.regid),
        strName(item.strName),
        strPath(item.strPath),
        strParameters(item.strParameters),
        strPathConfig(item.strPathConfig),
        strPrefix(item.strPrefix),
        flags(item.flags),
        filter(item.filter),
        mask(item.mask),
        strUsername(item.strUsername),
        strPassword(item.strPassword),
        port(item.port)
    {
    }

    // Assign a device item
    _devItem& operator=(const _devItem& item)
    {
        id            = item.id;
        regid         = item.regid;
        strName       = item.strName;
        strPath       = item.strPath;
        strParameters = item.strParameters;
        strPathConfig = item.strPathConfig;
        strPrefix     = item.strPrefix;
        flags         = item.flags;
        filter        = item.filter;
        mask          = item.mask;
        strUsername   = item.strUsername;
        strPassword   = item.strPassword;
        port          = item.port;

        return *this;
    }

} devItem;

typedef devItem *PDEVITEM;

#endif
