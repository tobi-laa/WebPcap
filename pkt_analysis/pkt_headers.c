/** 
 * pkt_headers.c
 * 
 * @author: Tobias Laatsch
 * @version: 0.001
 * @date: 2013-04-28
 */

#include <sys/types.h>
#include <netdb.h>
#include "pkt_headers.h"

// FIXME: documentation
int get_ipv4_hlen(ipv4h *header){
    return 4 * ((header->v_hl) & 0x0f);
}

// FIXME: documentation
int get_tcp_hlen(tcph *header){
    return 4 * ((ntohs(header->off_flag)) >> 12);
}