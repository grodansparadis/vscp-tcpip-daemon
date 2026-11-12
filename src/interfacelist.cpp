// interfacelist.cpp
//
// This file is part of the VSCP (https://www.vscp.org) 
//
// Copyright (C) 2000-2026 Ake Hedman and contributors, the VSCP Project <info@vscp.org>
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

#ifdef __GNUG__
    //#pragma implementation
#endif

#include <string>
#include <deque>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "interfacelist.h"


///////////////////////////////////////////////////////////////////////////////
// Constructor
//

CInterfaceItem::CInterfaceItem( void )
{
    m_ipaddress = "127.0.0.1";
    m_macaddress = "";
}

///////////////////////////////////////////////////////////////////////////////
// Destructor
//

CInterfaceItem::~CInterfaceItem( void )
{

}


//*****************************************************************************
//                          CInterfaceList
//*****************************************************************************


///////////////////////////////////////////////////////////////////////////////
// Constructor
//

CInterfaceList::CInterfaceList( void )
{
  m_tcpclientlist.clear();
}

///////////////////////////////////////////////////////////////////////////////
// Destructor
//

CInterfaceList::~CInterfaceList( void )
{
  ;
}

///////////////////////////////////////////////////////////////////////////////
// addInterface
//
bool CInterfaceList::addInterface( const std::string& ip, const std::string& mac, const std::string& guid )
{
    CInterfaceItem *pItem = new CInterfaceItem;
    if ( NULL == pItem ) return false;

    pItem->m_ipaddress = ip ;
    pItem->m_macaddress = mac;
    pItem->m_guid.getFromString( guid );

    // Add the user
    m_tcpclientlist.push_back( pItem );
    
    return true;
}


///////////////////////////////////////////////////////////////////////////////
// addInterface
//
bool CInterfaceList::addInterface( const std::string& ip, const std::string& mac, const cguid& guid )
{
    CInterfaceItem *pItem = new CInterfaceItem;
    if ( NULL == pItem ) return false;

    pItem->m_ipaddress = ip ;
    pItem->m_macaddress = mac;
    pItem->m_guid = guid;

    // Add the user
    m_tcpclientlist.push_back( pItem );
    
    return true;
}