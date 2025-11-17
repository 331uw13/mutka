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


#ifdef MUTKA_CLIENT

    // Mutka client config flags (for: mutka_client_cfg)
    
    #define MUTKA_CCFLG_HAS_IDENTITY_KEYS (1 << 0)
    #define MUTKA_CCFLG_CONFIG_VALIDATED (1 << 1)

    // Mutka client flags (for: struct mutka_client)
    
    #define MUTKA_CLFLG_SHOULD_DISCONNECT (1 << 2)
    #define MUTKA_CLFLG_WAITING_CAPTCHA_INPUT (1 << 3)
    

#elifdef MUTKA_SERVER
    // Mutka server side client flags (for: struct mutka_client)
    
    #define MUTKA_SCFLG_CAPTCHA_COMPLETE (1 << 0)

    // Client and server have exchanged metadata keys.
    #define MUTKA_SCFLG_MTDATAKEYS_EXCHANGED (1 << 1)

    // Client responded with MPACKET_METADATA_KEY_EXHCANGE_COMPLETE
    // to metadata key exchange.
    #define MUTKA_SCFLG_MTDATAKEYS_COMPLETE (1 << 2)

    // Client has been completely verified and can send messages.
    #define MUTKA_SCFLG_VERIFIED (1 << 3)
    

#endif


struct mutka_client;

struct mutka_client_cfg {
    int flags;

    char  nickname [MUTKA_NICKNAME_MAX];
    bool  use_default_cfgdir;
    char  mutka_cfgdir [MUTKA_PATH_MAX]; // Modified by 'mutka_validate_client_cfg()'
                                         // If 'use_default_cfgdir' is set to 'true'
    
    // Config paths are set by mutka_validate_client_cfg()
    char  trusted_peers_dir        [MUTKA_PATH_MAX];
    char  trusted_hosts_path       [MUTKA_PATH_MAX];
    char  private_identity_path    [MUTKA_PATH_MAX];
    char  public_identity_path     [MUTKA_PATH_MAX];
    
    key_mldsa87_priv_t  identity_privkey;
    key_mldsa87_publ_t  identity_publkey;


    // If the server has captcha enabled
    // client must confirm it before it can fully connect.
    // 'char* captcha' is captcha image in ascii "art" form.
    // When user input is ready, mutka_send_captcha_answer() can be used.
    // 
    // NOTE: Currently the captcha letters can be only uppercase, be flipped vertically and/or horizontally.
    void(*confirm_server_captcha)
        (struct mutka_client*, char* /*captcha_buffer*/);


    // Called when client connects to server for the first time
    // or doesnt have the received server public key in "trusted_hosts" file.
    // 
    // This callback can return 'true' if public key is allowed to be added.
    // If 'false' is returned, MUTKA_CLFLG_SHOULD_DISCONNECT is set.
    bool(*accept_new_trusted_host_callback)
        (struct mutka_client*, struct mutka_str* /*not used*/);


    // If client receives a different host public key than it has saved in "trusted_hosts" file. 
    // A clear warning must be made and ask if allow to overwrite the existing public key.
    //
    // This callback can return 'true' to accept the key to be overwritten(MAY BE RISKY!)
    // and if 'false' is returned (no overwrite allowed), then MUTKA_CLFLG_SHOULD_DISCONNECT is set.
    //
    // IMPORTANT NOTE:
    //   It should be obvious to the user that overwriting the host key
    //   without consideration is very risky.
    //   Because if the key ever changes it means someone might be tampering with 
    //   the server's files or trying to execute a MITM attack.
    //   Thus overwriting the key before contacting the server admin is risky move.
    bool(*accept_hostkey_change_callback)
        (struct mutka_client*, struct mutka_str* /*not used*/);

};



struct mutka_client {
    
    int flags;

    enum mutka_env       env;
    int                  socket_fd;
    struct sockaddr_in   socket_addr;

    // Metadata keys.
    struct mutka_cipher_keys mtdata_keys;


#ifdef MUTKA_CLIENT // (Not on server side)
    
    pthread_mutex_t      mutex;
    
    struct mutka_client_cfg config;
 
    char                host_addr [MUTKA_HOST_ADDR_MAX];
    char                host_port [MUTKA_HOST_PORT_MAX];
    uint32_t            host_addr_len;
    uint32_t            host_port_len;
    key_mldsa87_publ_t  host_mldsa87_publkey;

    uint8_t   client_nonce[16];

    struct mutka_raw_packet  out_raw_packet;
    struct mutka_packet      inpacket; // Last received parsed packet.
    
    void(*packet_received_callback)(struct mutka_client*);


#elifdef MUTKA_SERVER // (Not on client side)

    int uid; // Random unique ID.

    // Expected captcha answer.
    char exp_captcha_answer [MUTKA_CAPTCHA_MAX]; 
    int8_t captcha_retries_left;    

#endif
};


bool mutka_validate_client_cfg      (struct mutka_client_cfg* config, char* nickname);
bool mutka_client_identity_exists   (struct mutka_client_cfg* config);
bool mutka_new_client_identity      (struct mutka_client_cfg* config, char* privkey_passphase, size_t passphase_len);
bool mutka_decrypt_client_identity  (struct mutka_client_cfg* config, char* passphase, size_t passphase_len);
bool mutka_read_public_identity     (struct mutka_client_cfg* config);

struct mutka_client* mutka_connect(struct mutka_client_cfg* config, char* host, char* port);
void mutka_init_metadata_key_exchange(struct mutka_client* client);
void mutka_send_captcha_answer(struct mutka_client* client, char* answer, size_t answer_len);

// This function behaves little bit differently depending on the
// Environment which the function was called from MUTKA_ENV_SERVER or MUTKA_ENV_CLIENT
void mutka_disconnect(struct mutka_client* client);



#endif
