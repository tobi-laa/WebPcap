#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define PORT 1337
#define BUFSIZE 1024

// short-short-int
typedef struct _ssi {
    short no1;
    short no2;
    int   no3;
} ssi;

int setSocketUp();

char *buffer;   // to hold any packets received
ssi *toSend;    // to cast the data correctly
int server;     // our server socket
int client;     // our client socket
int forked;     // parent or child process?

int main(){   
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
    
    if(client < 0) {
        fprintf(stderr, "ERROR: Client Connection error.\n");
        exit(EXIT_FAILURE);
    }
    
    fprintf(stdout,"New client accepted!\n");       
    fflush(stdout);
    
    buffer = malloc(BUFSIZE);

    int rd; // holds return value of read(...)
    while((rd = read(client, buffer, BUFSIZE)) > 0){
        if (rd != 8) {
            fprintf(stderr, "ERROR: Ignoring malformed package.\n");
            fflush(stderr);
            continue;
        }
        
        toSend = (ssi*) buffer;
        // fprintf(stdout,"%d %d %d\n",toSend->no1,toSend->no2,toSend->no3);
        // fflush(stdout);
        
        // increment each number
        toSend->no1++;
        toSend->no2++;
        toSend->no3++;
        
        // send the whole struct back
        write(client, toSend, sizeof(ssi));
    }
    
    fprintf(stderr, "Lost connection to client.\n");
    close(client);
    free(buffer);
    return 1;
}

/** This method creates a new socket, binds it to a specified IP/Port and sets it
 *  to listen for new connections. If successful, descriptor of this socket is
 *  returned, -1 otherwise. */
int setSocketUp(){
    //creates a TCP socket
    int server_sock = socket(AF_INET,SOCK_STREAM,0);
    if (server_sock < 0){
        fprintf(stderr, "ERROR: Socket could not be created. %s\n",strerror(errno));
        return -1;        
    }
    struct sockaddr_in *server=malloc(sizeof(struct sockaddr_in));
    // IPv4-address
    server->sin_family = AF_INET;
    //convert IP and port-no to network format
    server->sin_addr.s_addr = htonl(INADDR_ANY);//any network interface is okay
    server->sin_port = htons(PORT);
    if(bind(server_sock, (struct sockaddr*)server, sizeof(*server))<0){
        free(server);
        fprintf(stderr, "ERROR: Socket could not be bound to Port %hu. %s\n",PORT,strerror(errno));
        return -1;        
    }
    if(listen(server_sock,10)<0){
        free(server);
        fprintf(stderr, "ERROR: Socket could not be set to listen for connections. %s\n",strerror(errno));
        return -1;        
    }
    free(server);
    return server_sock;    
}