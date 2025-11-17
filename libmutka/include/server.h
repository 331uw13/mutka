#ifndef LIBMUTKA_SERVER_H
#define LIBMUTKA_SERVER_H

#include <stdint.h>
#include <netinet/in.h>
#include <pthread.h>

#include "client.h"
#include "packet.h"


// ---- Server config flags ----
#define MUTKA_SERVER_REUSEADDR         (1 << 0)
#define MUTKA_SERVER_CAPTCHA_ENABLED   (1 << 1)


struct mutka_server;

struct mutka_server_cfg {
    uint16_t port;
    uint32_t max_clients;
    int      flags;
    int8_t   max_captcha_retries;

    bool(*accept_new_hostkeys_callback)();
    void(*client_connected_callback)(struct mutka_server*, struct mutka_client*);
    void(*client_disconnected_callback)(struct mutka_server*, struct mutka_client*);
    void(*packet_received_callback)(struct mutka_server*, struct mutka_client*);
};


// IMPORTANT NOTE: Use mutex before accessing server variables.
struct mutka_server {
    pthread_mutex_t mutex;
    
    struct mutka_server_cfg config;
    struct sockaddr_in      socket_addr;
    int                     socket_fd;

    key_mldsa87_priv_t      host_mldsa87_privkey;
    key_mldsa87_publ_t      host_mldsa87_publkey;

    struct mutka_client*    clients;
    uint32_t                num_clients;

    struct mutka_raw_packet   out_raw_packet;
    struct mutka_packet       inpacket; // Last received parsed packet.

};

struct mutka_server* mutka_create_server
(
    struct mutka_server_cfg config,
    const char* hostkeys_path
);

void mutka_server_remove_client
(
    struct mutka_server* server,
    struct mutka_client* client
);

void mutka_close_server(struct mutka_server* server);

#endif
