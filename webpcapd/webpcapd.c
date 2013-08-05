#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <ifaddrs.h>
#include <pcap.h>
#include <glib.h>

#define SNAP_LEN 65535  /* should be enough to hold any packet */
#define PROMISC 0       /* capture in promiscuous mode or not? */
#define TO_MS 1024      /* based on the value tcpdump uses... */

#define PORT 31337
#define BUFSIZE 4096

#define DEF_FIL "not (host 127.0.0.1 or (tcp port 8080 and ("
#define OKAY "O"
#define ERROR "E"

typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

int setSocketUp();
void sendPacket(u_char *user, const struct pcap_pkthdr *h, const u_char *sp);
char *createDefaultFilter();

/* FIXME: check if first buffer is actually needed... */
char *buffer;       /* arbitrary buffer */
char *errbuf;       /* pcap error buffer */
char *user_filter = "none";
pcaprec_hdr_t *pktbuff;

/* FIXME: redirect stdout & stderr to a logfile */

int server, client; /* server & client sockets */

pcap_t *sdescr; /* session descriptor */

int pkthdrsz;

int count = 1;

int main() {    
    /* create socket */
    server = setSocketUp();
    if (server < 0)
        exit(EXIT_FAILURE);  
        
    while((client = accept(server, NULL, NULL)) >= 0) {
        int forked;         /* parent or child process? */
        if((forked = fork()) < 0) {
            fprintf(stderr, "ERROR: Client connection error.\n");
            return -1;
        }
        if(forked == 0) /* child process */
            break;
    }
    
    if(client < 0) { /* accept failed */
        fprintf(stderr, "ERROR: Client Connection error.\n");
        exit(EXIT_FAILURE);
    }
    
    fprintf(stdout,"New client accepted!\n");       
    fflush(stdout);

    /* initialize all three buffers */
    buffer = malloc(BUFSIZE);
    errbuf = malloc(sizeof(char) * PCAP_ERRBUF_SIZE);   
    pktbuff = malloc(sizeof(pcaprec_hdr_t));
    
    pkthdrsz = sizeof(pcaprec_hdr_t);
    
    char *filter;
    
    int flen;
    if((flen = read(client, buffer, BUFSIZE)) > 0) {
        user_filter = malloc(flen);
        strncpy(user_filter, buffer, flen);
    }
    filter = createDefaultFilter();
    
    char *dev;
    dev = "any";
    
    if ((sdescr = pcap_open_live(dev, SNAP_LEN, PROMISC, TO_MS, errbuf)) == NULL) {
        fprintf(stderr, "ERROR: Unable to open %s for capturing: %s\n", dev, errbuf);
        return close_session(-1);
    }

    guint32 net;  /* network address */
    guint32 mask; /* subnet mask */
    
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "ERROR: Unable to detect IP address settings for device %s: %s\n", dev, errbuf);
        net = mask = 0; /* use default values instead */
    }
    
    struct bpf_program fp; /* filter program */
    
    if (pcap_compile(sdescr, &fp, filter, 0, mask) == -1) {
        fprintf(stderr, "ERROR: Unable to parse filter %s: %s\n", filter, pcap_geterr(sdescr));
        write(client, ERROR, 1);
        return close_session(-1);
    }
    
    if (pcap_setfilter(sdescr, &fp) == -1) {
        fprintf(stderr, "ERROR: Unable to install filter %s: %s\n", filter, pcap_geterr(sdescr));
        write(client, ERROR, 1);
        return close_session(-1);
    }
  
    fprintf(stdout,"Successfully opened interface %s for capturing.\n", dev);
    write(client, OKAY, 1);

   
    /* FIXME: this is basically an infinte loop atm */
    pcap_loop(sdescr, -1, sendPacket, NULL);    
    
    return close_session(1);
}

int close_session(exit_code) {
    pcap_close(sdescr);
    
    close(client);
    
    free(buffer);
    free(errbuf);
    free(pktbuff);
    
    return exit_code;
}

/** This method creates a new socket, binds it to a specified IP/Port and sets it
 *  to listen for new connections. If successful, descriptor of this socket is
 *  returned, -1 otherwise. */
int setSocketUp() {
    /* creates a TCP socket */
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0){
        fprintf(stderr, "ERROR: Socket could not be created. %s\n",strerror(errno));
        return -1;        
    }
    struct sockaddr_in *server=malloc(sizeof(struct sockaddr_in));
    /* IPv4-address */
    server->sin_family = AF_INET;
    /* convert IP and port-no to network format */
    server->sin_addr.s_addr = htonl(INADDR_ANY); /* any network interface is okay */
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

void sendPacket(u_char *user, const struct pcap_pkthdr *h, const u_char *sp) {
    pktbuff->ts_sec   = (guint32) h->ts.tv_sec;
    pktbuff->ts_usec  = (guint32) h->ts.tv_usec;
    pktbuff->incl_len = h->caplen;
    pktbuff->orig_len = h->len;
    
    write(client, pktbuff, pkthdrsz);   /* send pcap header */
    write(client, sp, h->caplen);       /* send actual captured packet */
}

/* FIXME */
char *createDefaultFilter() {
    char *filter = malloc(sizeof(char) * BUFSIZE);
    strncpy(filter, DEF_FIL, sizeof(DEF_FIL));
    
    struct ifaddrs *ifaddr, *ifa;
    int s;
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
    
    strncat(filter, ")))", BUFSIZE - strlen(filter));

    if (strcmp(user_filter, "none")) { /* user wants to specify filter */
        strncat(filter, " and ", BUFSIZE - strlen(filter));
        strncat(filter, user_filter, BUFSIZE - strlen(filter));
    }
    
    freeifaddrs(ifaddr);
    
    free(user_filter);
    
    return filter;
}
