/** 
 * pkt_headers.h
 * 
 * @author: Tobias Laatsch
 * @version: 0.001
 * @date: 2013-04-28
 */

#include <sys/types.h>
#include <netdb.h>

/*
 ******************************************************************
 ****************** LINK-LAYER HEADER TYPES ***********************
 ******************************************************************
 */

#define ETH_HLEN 14         // Ethernet frame length in bytes
#define ETH_ALEN  6         // MAC address length in bytes

typedef struct _ethh {
    u_char dst[ETH_ALEN];   // destination MAC address
    u_char src[ETH_ALEN];   // source MAC address
    u_short prot;           // protocol (i.e. IPv4)
} ethh;

// FIXME: add 802.11 support

/*
 ******************************************************************
 ***************** NETWORK LAYER HEADER TYPES *********************
 ******************************************************************
 */

typedef struct _ipv4h {
    u_char v_hl;            // version & IP header length
    u_char tos;             // type of service
    u_short tlen;           // total length
    u_short id;             // identification
    u_short frag;           // fragmentation flags & offset
    u_char ttl;             // time to live
    u_char prot;            // protocol (i.e. TCP)
    u_short csum;           // header checksum
    struct in_addr src;     // source IPv4 address
    struct in_addr dst;     // destination IPv4 address
    /* various options may follow; it is virtually impossible
     * though to specify them within this struct */
} ipv4h;

// FIXME: documentation
int get_ipv4_hlen(ipv4h *header);

#define IPV6_HLEN 40        // IPv6 header length in bytes
#define IPV6_ALEN 16        // IPv6 address length in bytes

typedef struct _ipv6h {
    u_short plen;           // payload length
    u_char nh;              // next header; same as protocol for ipv4h
    u_char hlim;            // hop limit
    // FIXME: need to check for some appropriate data types here 
    u_char src[IPV6_ALEN];  // source IPv6 address
    u_char dst[IPV6_ALEN];  // destination IPv6 address
} ipv6h;

// FIXME: add ARP support (amongst others)

/*
 ******************************************************************
 *************** TRANSPORT LAYER HEADER TYPES *********************
 ******************************************************************
 */

typedef struct _tcph {
    u_short sport;          // source port
    u_short dport;          // destination port
    u_int seqn;             // sequence number
    u_int ackn;             // ACK number
    // FIXME: maybe split the following in two chars?
    u_short off_flag;       // data offset, reserved portion, flags
    u_short wsize;          // window size
    u_short csum;           // header checksum
    u_short urg;            // urgent pointer
    /* various options may follow; it is virtually impossible
     * though to specify them within this struct */
} tcph;

// FIXME: documentation
int get_tcp_hlen(tcph *header);

#define UDP_HLEN 8          // UDP header length in bytes

typedef struct _udph {
    u_short sport;          // source port
    u_short dport;          // destination port
    u_short len;            // length of payload incl. UDP header
    u_short csum;           // header checksum
} udph;

// FIXME: add ICMP support (amongst others)

/*
 ******************************************************************
 *************** APPLICATION LAYER HEADER TYPES *********************
 ******************************************************************
 */
// FIXME: There's nothing as of yet