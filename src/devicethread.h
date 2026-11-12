// devicethread.h
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

/*!
    @file devicethread.h
    @brief Interface for the device threads in the VSCP daemon.

    This file contains the declarations for the device threads used in the VSCP daemon.
    It provides the necessary function prototypes for handling device communication
    at both Level 1 and Level 2.

    @author Ake Hedman and contributors, the VSCP project
    @date 2000-2026
    @version 1.0
    @copyright Copyright (C) 2000-2026 Ake Hedman and contributors, the VSCP project
    @license MIT License
*/

#if !defined(DEVICETHREAD_H__7D80016B_5EFD_40D5_94E3_6FD9C324CC7B__INCLUDED_)
#define DEVICETHREAD_H__7D80016B_5EFD_40D5_94E3_6FD9C324CC7B__INCLUDED_

void *
deviceThread(void *pData);

void *
deviceLevel1ReceiveThread(void *pData);
void *
deviceLevel1WriteThread(void *pData);

void *
deviceLevel2ReceiveThread(void *pData);
void *
deviceLevel2WriteThread(void *pData);


#endif
