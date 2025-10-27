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



#define MUTKA_PATH_MAX 256

struct mutka_client_cfg {
    char*     host;
    uint16_t  port;
    char*     nickname;

    bool      use_default_cfgdir;
    char      mutka_cfgdir [MUTKA_PATH_MAX]; // Modified by 'mutka_validate_client_cfg()'
                                             // If 'use_default_cfgdir' is set to 'true'
    
    char      trusted_peers_dir [MUTKA_PATH_MAX];      // From mutka_validate_client_cfg()
    char      trusted_privkey_path [MUTKA_PATH_MAX];   // From mutka_validate_client_cfg()
    char      trusted_publkey_path [MUTKA_PATH_MAX];   // From mutka_validate_client_cfg()
    
    char      trusted_privkey[ED25519_KEYLEN];
    char      trusted_publkey[ED25519_KEYLEN];
};


bool mutka_validate_client_cfg(struct mutka_client_cfg* config);
bool mutka_cfg_trustedkeys_exists(struct mutka_client_cfg* config);

// Passphase is required for encrypting the trusted private key file.
bool mutka_cfg_generate_trustedkeys(struct mutka_client_cfg* config,
        char* privkey_passphase, size_t passphase_len);

bool mutka_decrypt_trusted_privkey
(
    struct mutka_client_cfg* config,
    char* passphase, size_t passphase_len
);

struct mutka_client* mutka_connect(struct mutka_client_cfg* config);

// This function behaves little bit differently depending on the
// Environment which the function was called from MUTKA_ENV_SERVER or MUTKA_ENV_CLIENT
void mutka_disconnect(struct mutka_client* client);



#endif
