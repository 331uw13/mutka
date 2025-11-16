#ifndef LIBMUTKA_CLIENT_H
#define LIBMUTKA_CLIENT_H

#include <pthread.h>
#include <sys/socket.h>

#include "packet.h"
#include "env.h"
#include "cryptography.h"


#define MUTKA_NICKNAME_MAX 24
#define MUTKA_PATH_MAX 256
#define MUTKA_HOST_ADDR_MAX 16
#define MUTKA_HOST_PORT_MAX 8
#define MUTKA_CAPTCHA_MAX 6

// Mutka client config flags (for: mutka_client_cfg)
#define MUTKA_CCFG_HAS_TRUSTED_PUBLKEY (1 << 0)
#define MUTKA_CCFG_HAS_TRUSTED_PRIVKEY (1 << 1)


// Mutka client flags (for: struct mutka_client)
#define MUTKA_CLFLG_SHOULD_DISCONNECT  (1 << 0)

// Mutka server client flags (for: struct mutka_client)
#define MUTKA_SCFLG_VERIFIED           (1 << 1) // "Client verified with password and/or captcha?"
#define MUTKA_SCFLG_MDKEYS_EXCHANGED   (1 << 2) // "Metadata keys exchanged?"



struct mutka_client;

struct mutka_client_cfg {
    char  nickname [MUTKA_NICKNAME_MAX];

    bool  use_default_cfgdir;
    char  mutka_cfgdir [MUTKA_PATH_MAX]; // Modified by 'mutka_validate_client_cfg()'
                                         // If 'use_default_cfgdir' is set to 'true'
    
    // Config paths are set by mutka_validate_client_cfg()
    char  trusted_peers_dir    [MUTKA_PATH_MAX];
    char  trusted_privkey_path [MUTKA_PATH_MAX];
    char  trusted_publkey_path [MUTKA_PATH_MAX];
    char  trusted_hosts_path   [MUTKA_PATH_MAX];

    char  trusted_privkey [ED25519_KEYLEN]; // From mutka_decrypt_trusted_privkey()
    char  trusted_publkey [ED25519_KEYLEN]; // From mutka_read_trusted_publkey()

    // Called when client connects to server for the first time
    // or doesnt have the received server signature in "trusted_hosts" file.
    // 
    // This callback can return 'true' if signature is allowed to be added.
    // If 'false' is returned, MUTKA_CLFLG_SHOULD_DISCONNECT is set.
    bool(*accept_new_trusted_host_callback)
        (struct mutka_client*, struct mutka_str* /*recv host signature*/);


    // If client receives a different host signature than it has saved in "trusted_hosts" file. 
    // A clear warning must be made and ask if allow to overwrite the existing signature.
    //
    // This callback can return 'true' to accept the signature to be overwritten(MAY BE RISKY!)
    // and if 'false' is returned (no overwrite allowed), then MUTKA_CLFLG_SHOULD_DISCONNECT is set.
    //
    // IMPORTANT NOTE:
    //   It should be obvious to the user that overwriting the host signature
    //   without consideration is very risky.
    //   Because if the signature ever changes it means someone might be tampering with 
    //   the server's files or trying to execute a MITM attack.
    //   Thus overwriting the signature before contacting the server admin is risky move.
    bool(*accept_host_signature_change_callback)
        (struct mutka_client*, struct mutka_str* /*recv host signature*/);

    int flags;
};



struct mutka_client {
    pthread_mutex_t      mutex;

    enum mutka_env       env;
    int                  socket_fd;
    struct sockaddr_in   socket_addr;

    // Metadata keys.
    struct mutka_cipher_keys mtdata_keys;


    // At client side these are its own local key pair.
    // And if at server side these are the client's serverside key pair
    //key128bit_t          metadata_publkey;
    //key128bit_t          metadata_privkey;

    // At client side this is serverside metadata public key.
    // And if at server side this is client's metadata public key.
    //key128bit_t          peer_metadata_publkey;

    // Shared key derived from peer public key and self private key
    // and passed through HKDF.
    //key128bit_t          metadata_shared_key;


    int flags;


#ifdef MUTKA_CLIENT // (Not on server side)
    
    struct mutka_client_cfg config;
 
    char      host_addr [MUTKA_HOST_ADDR_MAX];
    char      host_port [MUTKA_HOST_PORT_MAX];
    uint32_t  host_addr_len;
    uint32_t  host_port_len;

    uint8_t   client_nonce[16];

    key128bit_t              trusted_privkey;
    key128bit_t              trusted_publkey;
    key128bit_t              host_public_key;
    struct mutka_raw_packet  out_raw_packet;
    struct mutka_packet      inpacket; // Last received parsed packet.
    
    void(*packet_received_callback)(struct mutka_client*);


#elifdef MUTKA_SERVER // (Not on client side)

    int uid; // Random unique ID.

    // Expected captcha answer.
    char exp_captcha_answer [MUTKA_CAPTCHA_MAX]; 

#endif
};


bool mutka_validate_client_cfg(struct mutka_client_cfg* config, char* nickname);
bool mutka_cfg_trustedkeys_exists(struct mutka_client_cfg* config);

// Passphase is required for encrypting the trusted private key file.
bool mutka_cfg_generate_trustedkeys
(
    struct mutka_client_cfg* config,
    char* privkey_passphase, size_t passphase_len
);

bool mutka_decrypt_trusted_privkey
(
    struct mutka_client_cfg* config,
    char* passphase, size_t passphase_len
);


// Trusted public key is not encrypted.
bool mutka_read_trusted_publkey(struct mutka_client_cfg* config);

struct mutka_client* mutka_connect(struct mutka_client_cfg* config, char* host, char* port);

void mutka_init_metadata_key_exchange(struct mutka_client* client);

// This function behaves little bit differently depending on the
// Environment which the function was called from MUTKA_ENV_SERVER or MUTKA_ENV_CLIENT
void mutka_disconnect(struct mutka_client* client);



#endif
