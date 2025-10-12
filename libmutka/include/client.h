#ifndef LIBMUTKA_CLIENT_H
#define LIBMUTKA_CLIENT_H

#include <sys/socket.h>

#include "packet.h"



struct mutka_client {
    int                 socket_fd;
    struct sockaddr_in  socket_addr;
   
    struct mutka_raw_packet out_raw_packet; 
    struct mutka_packet     inpacket; // Last received parsed packet.
};


struct mutka_client* mutka_connect(const char* host, uint16_t port);
void                 mutka_disconnect(struct mutka_client* client);




#endif
