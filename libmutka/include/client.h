#ifndef LIBMUTKA_CLIENT_H
#define LIBMUTKA_CLIENT_H

#include <pthread.h>
#include <sys/socket.h>

#include "packet.h"
#include "env.h"
#include "cryptography.h"


#define MUTKA_NICKNAME_MAX 24


struct mutka_client {
    pthread_mutex_t      mutex;

    enum mutka_env       env;
    int                  socket_fd;
    struct sockaddr_in   socket_addr;
    struct mutka_str     peer_metadata_publkey;


    // ======( Not available on server side )======
    
    struct mutka_keypair metadata_keys;
     
    struct mutka_raw_packet out_raw_packet;
    struct mutka_packet     inpacket; // Last received parsed packet.
    
    void(*packet_received_callback)(struct mutka_client*);
    bool handshake_complete;
};

struct mutka_client_cfg {
    char*     host;
    uint16_t  port;
    char*     mutka_cfgdir;
    char*     nickname;
    
    size_t mutka_cfgdir_size;
    size_t nickname_size;
};


bool mutka_cfg_trustedkey_exists(struct mutka_client_cfg* config);
bool mutka_cfg_generate_trustedkey(struct mutka_client_cfg* config);

struct mutka_client* mutka_connect(struct mutka_client_cfg* config);

// This function behaves little bit differently depending on the
// Environment which the function was called from MUTKA_ENV_SERVER or MUTKA_ENV_CLIENT
void mutka_disconnect(struct mutka_client* client);



#endif
