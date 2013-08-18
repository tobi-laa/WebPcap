#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <ifaddrs.h>
#include <pcap.h>

#define SNAP_LEN 65535  /* should be enough to hold any packet */
#define PROMISC 0       /* capture in promiscuous mode or not? */
#define TO_MS 1024      /* based on the value tcpdump uses... */

#define PORT 31337      /* port used by this program */
#define WS_PORT 8080    /* port used by the webserver communicating with us */
#define BUFSIZE 128

#define OKAY "O"
#define ERROR "E"

#define USAGE "Usage: %s [-p|--port PORT] [-wp|--webserverport PORT]\n"

#define IF_ERROR "ERROR: Could not determine interfaces. %s\n"
#define CL_ERROR "ERROR: Client connection error %s.\n"
#define CAP_ERROR "ERROR: Unable to open 'any' for capturing: %s\n"
#define PFIL_ERROR "ERROR: Unable to parse filter %s: %s\n"
#define IFIL_ERROR "ERROR: Unable to install filter %s: %s\n"
#define SOCK_CR_ERROR "ERROR: Socket could not be created. %s\n"
#define SOCK_BN_ERROR "ERROR: Socket could not be bound to Port %hu. %s\n"
#define SOCK_LS_ERROR "ERROR: Socket could not be set to listen for connections. %s\n"

#define CAP_WARN "WARNING: Unable to detect IP address settings for 'any' device: %s\n"

int set_socket_up();
char *read_user_filter(char * buffer);
char *create_default_filter(char * user_filter, int port, int ws_port);
int close_session(int exit_code);
void *increase_buffer_size(void *old_buffer);

/* everything to be closed and freed is global */
char *buffer; /* arbitrary buffer */
char *errbuf; /* pcap error buffer */
char *filter; /* will hold filter expression */

int server, client; /* server & client sockets */

pcap_t *cap_handle, *client_handle; /* capture (live) and client handle */
FILE * client_file; /* pseudo-file wrapper around client fd */
pcap_dumper_t * client_dumper; /* used to write to client_file */

int main(int argc, char *argv[]) {   
    /**************************** declare variables ***************************/
    int port, ws_port;     /* this apps port and webservers port */
    int forked;            /* parent or child process? */
    bpf_u_int32 net, mask; /* network address, subnet mask */
    struct bpf_program fp; /* filter program */

    /**************************** initialize variables*************************/    
    port = PORT;
    ws_port = WS_PORT;
    buffer = errbuf = filter = NULL;
    cap_handle = client_handle = NULL;
    client_file = NULL;
    client_dumper = NULL;
    server = client = -1;
    
    /*********************** read in stdin commands ***************************/
    if (argc > 5 || (argc % 2) == 0) { /* invalid number of commands */
        fprintf(stdout, USAGE, argv[0]);
        return close_session(1);
    }
    else {
        int i;
        for (i = 1; i < argc - 1; i++) {
            if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port"))
                port = atoi(argv[++i]);
            
            else if (!strcmp(argv[i], "-wp") || 
                     !strcmp(argv[i], "--webserverport"))
                ws_port = atoi(argv[++i]);
            
            else {
                fprintf(stdout, USAGE, argv[0]);
                return close_session(1);
            }
        }
    }
    
    /********* create server socket and wait for clients **********************/
    server = set_socket_up(port);
    if (server < 0)
        return close_session(-1);  
        
    while((client = accept(server, NULL, NULL)) >= 0) {
        if ((forked = fork()) < 0) {
            fprintf(stderr, CL_ERROR, strerror(errno));
            return close_session(-1);
        }
        if (forked == 0) /* child process */
            break;
    }
    
    /********************* !!!!THIS IS A CLIENT NOW!!!! ***********************/
    fprintf(stdout, "Successfully accepted a new client.\n");
    /********************** create (live) capture handle **********************/
    if ((cap_handle = pcap_create("any", errbuf)) == NULL) {
        fprintf(stderr, CAP_ERROR, errbuf);
        return close_session(-1);
    }
    if (pcap_set_snaplen(cap_handle, SNAP_LEN) == -1) {
        fprintf(stderr, CAP_ERROR, errbuf);
        return close_session(-1);
    }
    if (pcap_set_promisc(cap_handle, PROMISC) == -1) {
        fprintf(stderr, CAP_ERROR, errbuf);
        return close_session(-1);
    }
    if (pcap_set_timeout(cap_handle, TO_MS) == -1) {
        fprintf(stderr, CAP_ERROR, errbuf);
        return close_session(-1);
    }
    if (pcap_activate(cap_handle) == -1) {
        fprintf(stderr, CAP_ERROR, errbuf);
        return close_session(-1);
    }
    
    fprintf(stdout, "Successfully opened interface 'any' for capturing.\n");
    
    /****************** handle client, initialize pseudo-file etc *************/
    server = -1; /* server socket not used by client */
    
    if (client < 0) { /* accept failed */
        fprintf(stderr, CL_ERROR, strerror(errno));
        return close_session(-1);
    }    
    if ((client_file = fdopen(client, "w")) == NULL) {
        fprintf(stderr, CL_ERROR, strerror(errno));
        return close_session(-1);
    }    
    if ((client_handle = pcap_open_dead(pcap_datalink(cap_handle), SNAP_LEN)) 
        == NULL) {
        fprintf(stderr, CL_ERROR, errbuf);
        return close_session(-1);
    }    
    if ((client_dumper = pcap_dump_fopen(client_handle, client_file)) == NULL) {
        fprintf(stderr, CL_ERROR, errbuf);
        return close_session(-1);
    }
    
    /******************* read, create and install filter **********************/
    /* initialize all buffers */
    errbuf = malloc(sizeof(char) * PCAP_ERRBUF_SIZE);
    buffer = read_user_filter(malloc(BUFSIZE));
    
    if ((filter = create_default_filter(buffer, port, ws_port)) == NULL)
        /* error message provided by create_default_filter */
        return close_session(-1);

    if (pcap_lookupnet("any", &net, &mask, errbuf) == -1) {
        fprintf(stderr, CAP_WARN, errbuf);
        net = mask = 0; /* use default values instead */
    }    
    if (pcap_compile(cap_handle, &fp, filter, 0, mask) == -1) {
        fprintf(stderr, PFIL_ERROR, filter, pcap_geterr(cap_handle));
        write(client, ERROR, 1);
        return close_session(-1);
    }    
    if (pcap_setfilter(cap_handle, &fp) == -1) {
        fprintf(stderr, IFIL_ERROR, filter, pcap_geterr(cap_handle));
        write(client, ERROR, 1);
        return close_session(-1);
    }
    
    fprintf(stdout, "Successfully created filter expression '%s'.\n", filter);
    /* filter not needed anymore */
    free(filter);
    filter = NULL;
    
    /*************************** start capturing ******************************/
    
    write(client, OKAY, 1);
   
    /* this is basically an infinte loop atm */
    pcap_loop(cap_handle, -1, pcap_dump, (u_char *) client_dumper);
    
    return close_session(-1);
}

char* read_user_filter(char * buffer) {
    char buff;
    int filter_len;
    
    filter_len = 0;
    
    while (read(client, &buff, 1) > 0) {
        /* make sure the filter expression fits inside our buffer */
        if (filter_len == sizeof(buffer))
            buffer = increase_buffer_size(buffer);
        
        buffer[filter_len++] = buff;
        if (buff == '\0') /* filter expression termination.. */
            break;
    }
    
    return buffer;
}

int close_session(int exit_code) {
    if (client_dumper != NULL) pcap_dump_close(client_dumper);
    /* FIXME for some reason this causes memory errors? */
    /* if (client_file != NULL)   fclose(client_file); */
    if (client_handle != NULL) pcap_close(client_handle);
    if (cap_handle != NULL)    pcap_close(cap_handle);

    if (buffer != NULL) free(buffer);
    if (errbuf != NULL) free(errbuf);
    if (filter != NULL) free(filter);
    if (client > 0) close(client);
    if (server > 0) close(server);
    
    return exit_code;
}

/** This method creates a new socket, binds it to a specified IP/Port and sets 
 *  it to listen for new connections. If successful, descriptor of this socket
 *  is returned, -1 otherwise. */
int set_socket_up(int port) {
    /* creates a TCP socket */
    int server_sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (server_sock < 0){
        fprintf(stderr, SOCK_CR_ERROR, strerror(errno));
        return -1;        
    }
    struct sockaddr_in6 *server = malloc(sizeof(struct sockaddr_in6));
    server->sin6_family = AF_INET6;
    server->sin6_addr = in6addr_any; /* any interface is okay */
    server->sin6_port = htons(port);
    if (bind(server_sock, (struct sockaddr*)server, sizeof(*server)) < 0){
        free(server);
        fprintf(stderr, SOCK_BN_ERROR, port, strerror(errno));
        return -1;        
    }
    if (listen(server_sock, 10) < 0){
        free(server);
        fprintf(stderr, SOCK_LS_ERROR, strerror(errno));
        return -1;        
    }
    free(server);
    return server_sock;    
}

/* This method doubles the size of an existing buffer, preserving its contents. 
 */
void *increase_buffer_size(void *old_buffer) {
    int n;
    void *buffer;
    
    n = sizeof(old_buffer);
    buffer = malloc(n << 1);
    
    memcpy(buffer, old_buffer, n);    
    free(old_buffer);
    
    return buffer;
}

/* This method takes user_filter as an input and creates the appropriate filter
 * expression for starting a capture. The format of the default filter 
 * expression is
 * 
 * not (tcp port port or tcp port ws_port and (host IP_1 or host IP_2))
 * 
 * to which a user specified may be added in the case it was specified. The
 * resulting filter expression is returned.
 */
char *create_default_filter(char * user_filter, int port, int ws_port) {
    int filter_len, errnum; /* length of char * filter below, error number */
    struct ifaddrs *interfaces, *iter; /* for iterating interface infos */
    char host[NI_MAXHOST]; /* interface addresses will be stored here */
    char first_host; /* boolean variable. true for first address */
    char add_add; /* boolean variable, add address */
    char *filter; /* filter to be returned */

    /* try to get interface information */
    if (getifaddrs(&interfaces) == -1) {
        fprintf(stderr, IF_ERROR, strerror(errno));
        return NULL;
    }
    first_host = 1; /* true */
    add_add = 0; /* false */
    
    /***************** first run: determine filter_len ************************/
    
    /* start with enough space for any kind of port */
    filter_len = strlen("not (tcp port XXXXX or tcp port XXXXX and ())");

    for (iter = interfaces; iter != NULL; iter = iter->ifa_next) {
        if (iter->ifa_addr == NULL) /* ignore objects without addresses */
            continue;  

        if (iter->ifa_addr->sa_family == AF_INET) {
            add_add = 1;
            errnum = getnameinfo(iter->ifa_addr, sizeof(struct sockaddr_in),
                                 host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        }
        else if (iter->ifa_addr->sa_family == AF_INET6) {
            add_add = 1;
            errnum = getnameinfo(iter->ifa_addr, sizeof(struct sockaddr_in6),
                                 host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        }
        
        if (add_add) {
            if (errnum != 0) {
                fprintf(stderr, IF_ERROR, gai_strerror(errnum));
                return NULL;
            }
            if (first_host) { /* first address */
                /* strtok(host, "%") is to drop the scope for ipv6 addresses */
                filter_len += strlen("host ") + strlen(strtok(host, "%"));
                first_host = 0; /* false */                
            }
            else
                filter_len += strlen(" or host ") + strlen(strtok(host, "%"));
            
            add_add = 0;
        }
    }
    
    if (strcmp(user_filter, "none")) /* user wants to specify filter */
        filter_len += strlen(" and ") + strlen(user_filter);
    
    /***************** second run: build filter expression ********************/
    
    filter = malloc(filter_len);
    sprintf(filter, "not (tcp port %d or tcp port %d and (", port, ws_port);
    first_host = 1; /* true */
    
    for (iter = interfaces; iter != NULL; iter = iter->ifa_next) {
        if (iter->ifa_addr == NULL)
            continue;  

        if (iter->ifa_addr->sa_family == AF_INET) {
            add_add = 1;
            errnum = getnameinfo(iter->ifa_addr, sizeof(struct sockaddr_in),
                                 host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        }
        else if (iter->ifa_addr->sa_family == AF_INET6) {
            add_add = 1;
            errnum = getnameinfo(iter->ifa_addr, sizeof(struct sockaddr_in6),
                                 host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        }

        if (add_add) {
            if (errnum != 0) {
                fprintf(stderr, IF_ERROR, gai_strerror(errnum));
                free(filter);
                return NULL;
            }
            if (first_host) { /* first address */
                strcat(filter, "host ");
                strcat(filter, strtok(host, "%"));
                first_host = 0; /* false */
            }
            else {
                strcat(filter, " or host ");
                strcat(filter, strtok(host, "%"));
            }
            
            add_add = 0;
        }
    }
    strcat(filter, "))");
    
    if (strcmp(user_filter, "none")) { /* user wants to specify filter */
        strcat(filter, " and ");
        strcat(filter, user_filter);
    }
    
    /* cleanup and return */    
    freeifaddrs(interfaces);
    
    return filter;
}