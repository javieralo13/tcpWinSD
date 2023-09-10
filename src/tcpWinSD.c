/*
 * tcpWinSD.c
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

#include "tcpWinSD.h"
#include "basicStats.h"  // <--

T2_PLUGIN_INIT_WITH_DEPS("tcpWinD", "0.8.11", 0, 8, "basicStats"); // <--


extern bSFlow_t *bSFlow __attribute__((weak)); // <--

/*
 * Plugin variables that may be used by other plugins (MUST be declared in
 * the header file as 'extern tcpWinFlow_t *tcpWiniFlows;'
 */
tcpWinFlow_t *tcpWinFlows;

// window size counts
gwz_t gwz;	    // <-- ip count structure
gwz_t *gwzP = &gwz; // <-- Pointer for later dependency experiments


/*
 * Function prototypes
 */


// Tranalyzer functions

/*
 * This describes the plugin name, version, major and minor version of
 * Tranalyzer required and dependencies
 */
//T2_PLUGIN_INIT("tcpWinSD", "0.8.10", 0, 8); i add PLUGIN with dependencies 


/*
 * This function is called before processing any packet.
 */
void initialize() {
    // allocate struct for all flows and initialise to 0
    T2_PLUGIN_STRUCT_NEW(tcpWinFlows);
}



/*
 * This function is called every time a new flow is created.
 */
void onFlowGenerated(packet_t *packet UNUSED, unsigned long flowIndex) {
    tcpWinFlow_t * const tcpWinFlowP = &tcpWinFlows[flowIndex];
    memset(tcpWinFlowP, '\0', sizeof(*tcpWinFlowP)); // set everything to 0

    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & L2_FLOW) return; // Layer 2 flow. No L3/4 pointers, so return
}


/*
 * This function is called for every packet with a layer 4.
 */
void claimLayer4Information(packet_t *packet, unsigned long flowIndex) {
    flow_t * const flowP = &flows[flowIndex];
    if (flowP->layer4Protocol != L3_TCP) return; // process only TCP

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

    tcpWinFlow_t * const tcpWinFlowP = &tcpWinFlows[flowIndex];
    const tcpHeader_t * const tcpHeader = (tcpHeader_t*)packet->layer4Header;
    const uint32_t tcpWin = ntohs(tcpHeader->window);

    tcpWinFlowP->pktTcpCnt++;	// <-- count all tcp packets

    if (tcpWin < TCPWIN_THRES) {            // is window size below threshold?
        tcpWinFlowP->winThCnt++;            // count the packet
        tcpWinFlowP->stat |= TCPWIN_THU;    // set the status bit
    }

}


void onFlowTerminate(unsigned long flowIndex) {
    const flow_t * const flowP = &flows[flowIndex]; //
    tcpWinFlow_t * const tcpWinFlowP = &tcpWinFlows[flowIndex];
	bSFlow_t * const bSFlowP = &bSFlow[flowIndex]; // <--

	//tcpWinFlowP->pktTcpCnt == bSFlowP->numTPkts
    const float f = (float)tcpWinFlowP->winThCnt/(float)tcpWinFlowP->pktTcpCnt; // factor
	
	//if (bSFlowP->numTPkts) f = (float)tcpWinFlowP->winThCnt/(float)bSFlowP->numTPkts; // <--
	
	
    if (tcpWinFlowP->winThCnt && tcpWinFlowP->pktTcpCnt >= TCPWIN_MINPKTS) { //
        const int wzi = gwz.wzi; // store element count in const local variable, makes the compiler happy

        if (wzi < TCPWIN_MAXWSCNT) { // If array full, stop saving
            int i; 
            for (i = 0; i < wzi; i++) if (gwz.wzip[i].IPv4.s_addr == flowP->srcIP.IPv4.s_addr) break; // does IP exist?

            if (f > gwz.wzCnt[i]) {                     // only update if count is greater than the previous one
                gwz.tcpCnt[i] = bSFlowP->numTPkts; // update tcp packet count
                gwz.wzCnt[i] = f;                       // update relative count
                if (i == wzi) {				// new one?
                    gwz.wzip[i] = flowP->srcIP;         // save new IP
					gwz.wzdstip[i] = flowP->dstIP;      // save destination IP
                    gwz.wzi++;                          // increment global window size counter
                }
            }	
        }
    }	
}



/*
 * This function is called once all the packets have been processed.
 * Cleanup all used memory here.
 */
void onApplicationTerminate() {

    free(tcpWinFlows); // free the tcpWinSD Flows

    // open TCPWIN statistics file
    FILE *fp;
    int i;
    char srcIP[INET6_ADDRSTRLEN];
	char dstIP[INET6_ADDRSTRLEN];

    fp = t2_open_file(baseFileName, TCPWIN_FNSUP, "w");
    if (UNLIKELY(!fp)) { // if file cannot be opened print warning and return;
        T2_PWRN("tcpWin", "Failed to allocate memory for: %s", TCPWIN_FNSUP);
        return;
    }

    fprintf(fp, "# IP\tdstIP\tpktTcpCnt\twinRelThCnt\n"); // print header

    for (i = 0; i < gwz.wzi; i++) {
        T2_IP_TO_STR(gwz.wzip[i], 4, srcIP, INET6_ADDRSTRLEN);                  // transfer IP to string
		T2_IP_TO_STR(gwz.wzdstip[i], 4, dstIP, INET6_ADDRSTRLEN);                  // transfer IP to string
        fprintf(fp, "%s\%s\t%"PRIu32"\t%f\n", srcIP,dstIP, gwz.tcpCnt[i], gwz.wzCnt[i]); // print in file
    }

    fclose(fp);

}
