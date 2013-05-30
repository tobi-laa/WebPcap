/** 
 * pkt_analysis.c
 * 
 * @author: Tobias Laatsch
 * @version: 0.001
 * @date: 2013-04-28
 */ 
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "pkt_headers.h"

#define SNAP_LEN 65535  // should be enough to hold any packet
#define PROMISC 0       // capture in promiscuous mode or not? 
#define TO_MS 1024      // based on the value tcpdump uses...

// FIXME: documentation
void printPacket(u_char *userarg, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void printIPv4Packet(u_char *userarg, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void printTCPPacket(u_char *userarg, const struct pcap_pkthdr *pkthdr, const u_char *packet, int plen);
void printUDPPacket(u_char *userarg, const struct pcap_pkthdr *pkthdr, const u_char *packet, int plen);
void printPayload(u_char *userarg, const struct pcap_pkthdr *pkthdr, const u_char *packet, int plen);

char *errbuf;

void printPacket(u_char *userarg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // FIXME: make link-layer header type variable
    
    // we know this is an ethernet frame; thus
    ethh *eth_header = (ethh*) packet;
    
    switch(ntohs(eth_header->prot)) {
        case 0x0800:
            fprintf(stdout, "Received an IPv4 packet.\n");
            printIPv4Packet(userarg, pkthdr, packet + ETH_HLEN);
            break;
        case 0x86DD:
            fprintf(stdout, "Received an IPv6 packet.\n");
            break;
        case 0x0806:
            fprintf(stdout, "Received an ARP packet.\n");
            break;
        case 0x8035:
            fprintf(stdout, "Received an RARP packet.\n");
            break;
        default:
            fprintf(stdout, "Received an unknown packet.\n");
            break;
    }
    
    fprintf(stdout,"\n\n");
}

void printIPv4Packet(u_char *userarg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    ipv4h *header = (ipv4h*) packet;
    
    // FIXME: check the checksum
    int hlen, plen; // header & payload length
    if((hlen = get_ipv4_hlen(header)) < 20) {
        fprintf(stderr, "Malformed IPv4 packet.");
        return;
    }
    if((plen = ntohs(header->tlen)) < hlen) {
        fprintf(stderr, "Malformed IPv4 packet.");
        return;
    }
    plen -= hlen;
        
    fprintf(stdout, "SRC: %s\n", inet_ntoa(header->src));
    fprintf(stdout, "DST: %s\n", inet_ntoa(header->dst));
    
    switch(header->prot) {
        case 0x01:
            fprintf(stdout, "Transport layer: ICMP\n");
            break;
        case 0x06:
            fprintf(stdout, "Transport layer: TCP\n");
            printTCPPacket(userarg, pkthdr, packet + hlen, plen);
            break;
        case 0x11:
            fprintf(stdout, "Transport layer: UDP\n");
            printUDPPacket(userarg, pkthdr, packet + hlen, plen);
            break;
        default:
            fprintf(stdout, "Transport layer: unknown\n");
            break;
    }
}

void printTCPPacket(u_char *userarg, const struct pcap_pkthdr *pkthdr, const u_char *packet, int plen) {
    tcph *header = (tcph*) packet;
    
    // FIXME: check the checksum
    int hlen;
    if(((hlen = get_tcp_hlen(header)) < 20) || plen < hlen) {
        fprintf(stderr, "Malformed TCP packet.");
        return;
    }      
    plen-=hlen;
    
    fprintf(stdout, "SRC Port: %u\n", ntohs(header->sport));
    fprintf(stdout, "DST Port: %u\n", ntohs(header->dport));  
    
    // FIXME
    // fprintf(stdout, "Seqnum: %u\n", header->seqn);
    // fprintf(stdout, "Acknum: %d\n", ntohl(header->ackn));
    
    printPayload(userarg, pkthdr, packet + hlen, plen);
}

void printUDPPacket(u_char *userarg, const struct pcap_pkthdr *pkthdr, const u_char *packet, int plen) {
    udph *header = (udph*) packet;
    
    // FIXME: check the checksum
    if(plen < UDP_HLEN) {
        fprintf(stderr, "Malformed UDP packet.");
        return;
    }      
    plen-=UDP_HLEN;
    
    // fprintf(stdout, "SRC Port: %u\n", ntohs(header->sport));
    fprintf(stdout, "DST Port: %u\n", ntohs(header->dport));  
    
    printPayload(userarg, pkthdr, packet + UDP_HLEN, plen);
}

void printPayload(u_char *userarg, const struct pcap_pkthdr *pkthdr, const u_char *packet, int plen) {
    fprintf(stdout,"Payload:\n");
    int rows = plen/16;
    int i,j; // for-loop
    for(i = 0; i < rows; i++) {
        for(j = 0; j < 16; j++) {
            fprintf(stdout,"%02X ",packet[i*16+j]);
        }
        fprintf(stdout,"\n");
    }
    for (j = 0; j < plen%16; j++) {
        fprintf(stdout,"%02X ",packet[rows*16+j]);
    }
}

int main(int argc,char* argv[]) {
    char *dev, *filter;
    char dev_set = 0; // 0 if no interface was specified by user
    char filter_set = 0; // 0 if no filter was specified by user
    int i; // for-loop
    
    for(i = 1; i < argc; i++) { //argv[0] does not need to be checked!
        if((strcmp(argv[i],"-i") == 0) && (i<argc-1)){
            dev = argv[i+1];
            dev_set = 1;
            i++; //skip the next item            
        }
        else if((strcmp(argv[i],"-f") == 0) && (i<argc-1)){
            filter = argv[i+1];
            filter_set = 1;
            i++; //skip the next item            
        }
        else { // invalid command line option
            fprintf(stdout,"Usage: %s [-i INTERFACE] [-f FILTER]\n", argv[0]);
            return 0;
        }
    }
    
    errbuf = malloc(sizeof(char) * PCAP_ERRBUF_SIZE); // initialize error buffer
    
    if(!dev_set) { // pcap has to do the work for us
        if ((dev = pcap_lookupdev(errbuf)) == NULL) {
            fprintf(stderr, "Unable to select default device for capturing: %s\n", errbuf);
            return -1;
        }
        dev_set = 1; // successfully selected 'default' interface
    } 
  
    //FIXME: might want to make this global
    pcap_t *sdescr; // session descriptor 

    if ((sdescr = pcap_open_live(dev, SNAP_LEN, PROMISC, TO_MS, errbuf)) == NULL) {
        fprintf(stderr, "Unable to open %s for capturing: %s\n", dev, errbuf);
        return -1;
    }
    
    fprintf(stdout,"Successfully opened interface %s for capturing.\n",dev);

    // FIXME: DEFINITELY want to support 802.11 as well
    if (pcap_datalink(sdescr) != DLT_EN10MB) {
        fprintf(stderr, "Unable to capture on %s: Only Ethernet supported at this point.\n", dev);
        return -1;
    }
    
    if(filter_set) { // we need to compile and install a filter
        u_int net;  // network address
        u_int mask; // subnet mask
        
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Unable to detect IP address settings for device %s: %s\n", dev, errbuf);
            net = mask = 0; // use default values instead
        }
        
        struct bpf_program fp; // filter program 
        
        if (pcap_compile(sdescr, &fp, filter, 0, mask) == -1) {
            fprintf(stderr, "Unable to parse filter %s: %s\n", filter, pcap_geterr(sdescr));
            return -1;
        }
        
        if (pcap_setfilter(sdescr, &fp) == -1) {
            fprintf(stderr, "Unable to install filter %s: %s\n", filter, pcap_geterr(sdescr));
            return -1;
        }
    }
    
    // FIXME: this is basically an infinte loop atm
    pcap_loop(sdescr, -1, printPacket, NULL);
      
    return 0;
}