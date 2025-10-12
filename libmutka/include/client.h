#ifndef LIBMUTKA_CLIENT_H
#define LIBMUTKA_CLIENT_H

#include <pthread.h>
#include <sys/socket.h>

#include "packet.h"
#include "cryptography.h"


struct mutka_client {
    pthread_mutex_t     mutex;

    int                 socket_fd;
    struct sockaddr_in  socket_addr;
   
    struct mutka_raw_packet out_raw_packet; 
    struct mutka_packet     inpacket; // Last received parsed packet.

    void(*packet_received_callback)(struct mutka_client*);


    struct mutka_keypair metadata_keys; 
    struct mutka_str     peer_metadata_publkey;
};


struct mutka_client* mutka_connect(const char* host, uint16_t port);
void                 mutka_disconnect(struct mutka_client* client);
void                 mutka_free_client(struct mutka_client* client);



#endif
