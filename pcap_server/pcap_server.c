#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>

#define SNAP_LEN 65535  // should be enough to hold any packet
#define PROMISC 0       // capture in promiscuous mode or not? 
#define TO_MS 1024      // based on the value tcpdump uses...

#define PORT 1337
#define BUFSIZE 1024

#define DEF_FIL "not (tcp port 8080 and ("

int setSocketUp();
void sendPacket(u_char *user, struct pcap_pkthdr *h, u_char *sp);
char *createDefaultFilter();

// FIXME: check if first buffer is actually needed...
char *buffer;   // arbitrary buffer
char *errbuf;   // pcap error buffer

// FIXME: redirect stdout & stderr to a logfile

int server, client; // server & client sockets

int main() {
    int forked;         // parent or child process?
    
    //create socket
    server = setSocketUp();
    if (server < 0)
        exit(EXIT_FAILURE);  
        
    while((client = accept(server, NULL, NULL)) >= 0) {        
        if((forked = fork()) < 0) {
            fprintf(stderr, "ERROR: Client connection error.\n");
            return -1;
        }
        if(forked == 0) // child process
            break;
    }
    
    if(client < 0) { // accept failed
        fprintf(stderr, "ERROR: Client Connection error.\n");
        exit(EXIT_FAILURE);
    }
    
    fprintf(stdout,"New client accepted!\n");       
    fflush(stdout);

    // initialize both buffers
    buffer = malloc(BUFSIZE);
    errbuf = malloc(sizeof(char) * PCAP_ERRBUF_SIZE);   

    char *dev, *filter;
    
    if ((dev = pcap_lookupdev(errbuf)) == NULL) {
        fprintf(stderr, "ERROR: Unable to select default device for capturing: %s\n", errbuf);
        return -1;
    }
  
    //FIXME: might want to make this global
    pcap_t *sdescr; // session descriptor 
    pcap_t *clientdescr; // handle for sending packets to client    
//     pcap_dumper_t *cl_dumper;
//     FILE *cl_file;
//     
//     cl_file = fdopen(client,"w");

    if ((sdescr = pcap_open_live(dev, SNAP_LEN, PROMISC, TO_MS, errbuf)) == NULL) {
        fprintf(stderr, "ERROR: Unable to open %s for capturing: %s\n", dev, errbuf);
        return -1;
    }
    
//     if ((clientdescr = pcap_open_dead(DLT_EN10MB, SNAP_LEN)) == NULL) {
//         fprintf(stderr, "ERROR: Unable to open fake handle: %s\n", errbuf);
//         return -1;
//     }   
//     
//     if((cl_dumper = pcap_dump_fopen(clientdescr, cl_file)) == NULL) {
//         fprintf(stderr, "ERROR: Unable to write packets to client: %s.\n", errbuf);
//         return -1;
//     }
    
    fprintf(stdout,"Successfully opened interface %s for capturing.\n",dev);
    fflush(stdout);

    // FIXME: DEFINITELY want to support 802.11 as well
    if (pcap_datalink(sdescr) != DLT_EN10MB) {
        fprintf(stderr, "ERROR: Unable to capture on %s: Only Ethernet supported at this point.\n", dev);
        return -1;
    }
    
    filter = createDefaultFilter();
    // fprintf(stdout, filter);
    // fflush(stdout);
    
    // FIXME: very ugly...
    if(1) { // we need to compile and install a filter
        u_int net;  // network address
        u_int mask; // subnet mask
        
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "ERROR: Unable to detect IP address settings for device %s: %s\n", dev, errbuf);
            net = mask = 0; // use default values instead
        }
        
        struct bpf_program fp; // filter program 
        
        if (pcap_compile(sdescr, &fp, filter, 0, mask) == -1) {
            fprintf(stderr, "ERROR: Unable to parse filter %s: %s\n", filter, pcap_geterr(sdescr));
            return -1;
        }
        
        if (pcap_setfilter(sdescr, &fp) == -1) {
            fprintf(stderr, "ERROR: Unable to install filter %s: %s\n", filter, pcap_geterr(sdescr));
            return -1;
        }
    }
    
    // FIXME: this is basically an infinte loop atm
    pcap_loop(sdescr, -1, sendPacket, NULL);    
    
    pcap_close(sdescr);
    
    close(client);
    
    free(buffer);
    free(errbuf);
    
    return 1;
}

/** This method creates a new socket, binds it to a specified IP/Port and sets it
 *  to listen for new connections. If successful, descriptor of this socket is
 *  returned, -1 otherwise. */
int setSocketUp() {
    //creates a TCP socket
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0){
        fprintf(stderr, "ERROR: Socket could not be created. %s\n",strerror(errno));
        return -1;        
    }
    struct sockaddr_in *server=malloc(sizeof(struct sockaddr_in));
    // IPv4-address
    server->sin_family = AF_INET;
    //convert IP and port-no to network format
    server->sin_addr.s_addr = htonl(INADDR_ANY); //any network interface is okay
    server->sin_port = htons(PORT);
    if(bind(server_sock, (struct sockaddr*)server, sizeof(*server))<0){
        free(server);
        fprintf(stderr, "ERROR: Socket could not be bound to Port %hu. %s\n",PORT, strerror(errno));
        return -1;        
    }
    if(listen(server_sock,10)<0){
        free(server);
        fprintf(stderr, "ERROR: Socket could not be set to listen for connections. %s\n", strerror(errno));
        return -1;        
    }
    free(server);
    return server_sock;    
}

// FIXME: send pcap_pkthdr as well
void sendPacket(u_char *user, struct pcap_pkthdr *h, u_char *sp) {
    // pcap_dump(user, h, sp);
    write(client, sp, h->caplen);
}

char *createDefaultFilter() {
    char *filter = malloc(sizeof(char) * BUFSIZE);
    strncpy(filter, DEF_FIL, sizeof(DEF_FIL));
    
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) 
    {
        fprintf(stderr, "ERROR: Could not determine interface addresses. %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    int counter = 0;    

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
    {
        if (ifa->ifa_addr == NULL)
            continue;  

        s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

        if (ifa->ifa_addr->sa_family==AF_INET)
        {
            if (s != 0)
            {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            if (counter)
                strncat(filter, " or ", BUFSIZE - strlen(filter));
            strncat(filter, "host ", BUFSIZE - strlen(filter));
            strncat(filter, host, BUFSIZE - strlen(filter));
            counter++;
        }
    }
    
    strncat(filter, "))", BUFSIZE - strlen(filter));

    freeifaddrs(ifaddr);
    
    return filter;
}