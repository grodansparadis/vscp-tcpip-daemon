// vscpd.h : main header file for the VSCPD application
//
// This file is part of the VSCP (https://www.vscp.org) 
//
// Copyright (C) 2000-2026 Ake Hedman,  contributors,, the VSCP project <info@vscp.org>
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

#if !defined(_VSCPD_H__INCLUDED_)
#define _VSCPD_H__INCLUDED_

#include <controlobject.h>

// Include the CANAL definitions
#include <canal.h>

#ifdef WIN32
#define VSCPD_DEFAULT_ROOT_FOLDER "c:\\ProgramData\\vscp\\vscpd\\"
#define VSCPD_DEFAULT_CONFIG_FILE "c:\\ProgramData\\vscp\\vscpd.json"
#else
#define VSCPD_DEFAULT_ROOT_FOLDER "/var/lib/vscp/vscpd/"
#define VSCPD_DEFAULT_CONFIG_FILE "/etc/vscp/vscpd.json"
#endif


/// Names of mutex's
#define CANALD_CLIENT_OBJ_MUTEX "____CANAL_CLIENT_OBJ_MUTEX____"
#define CANALD_DEVICE_OBJ_MUTEX "____CANAL_DEVICE_OBJ_MUTEX____"
#define CANALD_SEND_OBJ_MUTEX "____CANAL_SEND_OBJ_MUTEX____"
#define CANALD_RECEIVE_OBJ_MUTEX "____CANAL_RECEIVE_OBJ_MUTEX____"
#define CANALD_CLIENT_MUTEX "__CANAL_CLIENT_MUTEX__"

/////////////////////////////////////////////////////////////////////////////
// VSCPApp:
// See vscpd.cpp for the implementation of this class
//

class VSCPApp {
    
public:
    VSCPApp();

public:

    
    /*!
            Initialize the system
     */
    int init( std::string& strcfgfile, std::string& rootFolder );


    // Implementation

private:

};


/////////////////////////////////////////////////////////////////////////////


#endif // !defined(VSCPD_H__3D1CDB8C_8027_46D5_9284_67750BEA4B7E__INCLUDED_)
