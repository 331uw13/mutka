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
#define MUTKA_SERVER_PASSWORD_ENABLED  (1 << 2) // NOT IMPLEMENTED YET.
#define MUTKA_SERVER_KEEP_UNREAD_MSG   (1 << 3) // NOT IMPLEMENTED YET.


// Mutka server flags:

#define MUTKA_SFLG_SHUTDOWN (1 << 1)


struct mutka_server;

struct mutka_server_cfg {
    uint16_t port;
    uint8_t  max_clients;
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
    uint8_t                 num_clients;

    struct mutka_raw_packet   out_raw_packet;
    struct mutka_packet       inpacket; // Last received parsed packet.

    // This is used when a client requests
    // other client's info for encrypting messages.
    // See 'MPACKET_GET_CLIENTS'.
    char* tmp_peer_info;
    uint32_t tmp_peer_info_len;

    int flags;
};

struct mutka_server* mutka_create_server
(
    struct mutka_server_cfg config,
    const char* hostkeys_path
);

void mutka_server_disconnect_client
(
    struct mutka_server* server,
    int client_uid
);

void mutka_close_server(struct mutka_server* server);
struct mutka_client* mutka_server_find_client_by_uid(struct mutka_server* server, int uid);

#endif
