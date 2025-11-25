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

// If a client disconnects while
// someone has requested other client's message public keys.
// 'mutka_client.send_peerinfo_index'.
// For now this problem is solved by adding client disconnects
// to a queue and processed when this flag is not set.
#define MUTKA_SFLG_SENDING_CLIENT_MSGPUBLKEYS (1 << 0)


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
    uint8_t                num_clients;
    
    int*                    client_disconnect_queue; // Client uids who disconnected.
    uint32_t                num_clients_disconnecting;

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

void mutka_server_remove_client
(
    struct mutka_server* server,
    int client_uid
);

void mutka_close_server(struct mutka_server* server);


#endif
