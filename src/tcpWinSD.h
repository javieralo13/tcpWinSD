/*
 * tcpWinSD.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef __TCP_WINSD_H__
#define __TCP_WINSD_H__

// global includes

// local includes
#include "t2Plugin.h"
// user defines
/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */
#define TCPWIN_THRES    1           // tcp Window threshold for packet counts
#define TCPWIN_MINPKTS  30          // <-- Summary file: minimal tcp packets seen to start saving process
#define TCPWIN_MAXWSCNT 100         // <-- Summary file: maximal number of window size threshold count array elements
#define TCPWIN_FNSUP "_tcpwin.txt"  // <-- Summary file: file name supplement
/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */

// Status variable: stat
#define TCPWIN_THU 0x1 // TCPWIN threshold undershoot

// plugin structures
typedef struct { // always large variables first to limit memory fragmentation
        uint32_t pktTcpCnt;
        uint32_t winThCnt;
        uint8_t stat;
} tcpWinFlow_t;

typedef struct {                      // <-- Global win size structure
    ipAddr_t wzip[TCPWIN_MAXWSCNT];   // <-- IP Address array
    uint32_t tcpCnt[TCPWIN_MAXWSCNT]; // <-- window size count
    float wzCnt[TCPWIN_MAXWSCNT];     // <-- relative window size count
    int wzi;                          // <-- window size index
} gwz_t;                              // <--

// plugin struct pointer for potential dependencies
extern tcpWinFlow_t *tcpWinFlows;
extern gwz_t *gwzP; // dependency pointer to

#endif // __TCP_WINSD_H__
