// vscpd_caps.h
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

//
// This file contains server capabilities for the VSCP server
//

#if !defined(VSCPDCAPS)
#define VSCPDCAPS

#include "vscp.h"

// Server capabilities for HIGH END SERVER PROBE

#define VSCP_DAEMON_SERVER_CAPABILITIES_0 0
#define VSCP_DAEMON_SERVER_CAPABILITIES_1 0
#define VSCP_DAEMON_SERVER_CAPABILITIES_2 0
#define VSCP_DAEMON_SERVER_CAPABILITIES_3 0
#define VSCP_DAEMON_SERVER_CAPABILITIES_4 0
#define VSCP_DAEMON_SERVER_CAPABILITIES_5 0

// Fill info in LSB of 16-bit code
#define VSCP_DAEMON_SERVER_CAPABILITIES_6                                      \
    ((uint8_t)((VSCP_SERVER_CAPABILITY_TCPIP | VSCP_SERVER_CAPABILITY_UDP |    \
                VSCP_SERVER_CAPABILITY_MULTICAST_ANNOUNCE |                    \
                VSCP_SERVER_CAPABILITY_RAWETH | VSCP_SERVER_CAPABILITY_WEB |   \
                VSCP_SERVER_CAPABILITY_WEBSOCKET |                             \
                VSCP_SERVER_CAPABILITY_REST |                                  \
                VSCP_SERVER_CAPABILITY_MULTICAST_CHANNEL) >>                   \
               8))

// Fill info in LSB of 16-bit code
#define VSCP_DAEMON_SERVER_CAPABILITIES_7                                      \
    VSCP_SERVER_CAPABILITY_IP6 | VSCP_SERVER_CAPABILITY_IP4 |                  \
      VSCP_SERVER_CAPABILITY_SSL | VSCP_SERVER_CAPABILITY_TWO_CONNECTIONS

#endif
