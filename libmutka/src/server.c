#include <stdlib.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/stat.h>
#include <openssl/rand.h>

#define MUTKA_SERVER
#include "../include/server.h"
#include "../include/mutka.h"

#include "../include/ascii_captcha.h"


static struct server_global {
    pthread_t acceptor_thread;
    pthread_t recv_thread;
}
global;


#include <stdio.h>

static void p_lock_server_mutex_ifneed(struct mutka_server* server) {
    pthread_t self = pthread_self();
    if(self != global.recv_thread) {
        pthread_mutex_lock(&server->mutex);
    }
}

static void p_unlock_server_mutex_ifneed(struct mutka_server* server) {
    pthread_t self = pthread_self();
    if(self != global.recv_thread) {
        pthread_mutex_unlock(&server->mutex);
    }
}

void* mutka_server_acceptor_thread_func(void* arg);
void* mutka_server_recvdata_thread_func(void* arg);
void mutka_server_handle_packet(struct mutka_server* server, struct mutka_client* client);




static bool p_mutka_server_generate_host_signature
(
    struct mutka_server* server,
    const char* host_signature_path
){

    if(mutka_file_exists(host_signature_path)) {
        remove(host_signature_path);
    }

    if(!mutka_openssl_MLDSA87_sign(MUTKA_VERSION_STR"(HOST_SIGNATURE)",
                &server->host_signature,
                &server->host_mldsa87_publkey,
                MLDSA87_SIGN_GENERATED_PUBLKEY, 0)) {
        return false;
    }


    uint8_t hostfile_data
        [ sizeof(server->host_signature.bytes) +
          sizeof(server->host_mldsa87_publkey.bytes)] = { 0 };

    memmove(hostfile_data,
            server->host_signature.bytes, 
            sizeof(server->host_signature.bytes));

    memmove(hostfile_data + sizeof(server->host_signature.bytes),
            server->host_mldsa87_publkey.bytes, 
            sizeof(server->host_mldsa87_publkey.bytes));

    int fd = creat(host_signature_path, S_IRUSR);
    if(fd < 0) {
        mutka_set_errmsg("%s: %s", __func__, strerror(errno));
        return false;
    }

    if(write(fd, hostfile_data, sizeof(hostfile_data)) < 0) {
        mutka_set_errmsg("%s: %s", __func__, strerror(errno));
        close(fd);
        return false;
    }
   
    close(fd);
    return true;
}

static bool p_mutka_server_read_host_signature
(
    struct mutka_server* server,
    const char* host_signature_path
){
    bool result = false;

    if(!mutka_file_exists(host_signature_path)) {
        goto out;
    }

    if(mutka_file_size(host_signature_path) !=
              sizeof(server->host_mldsa87_publkey.bytes) +
              sizeof(server->host_signature.bytes)) {
        goto out;
    }
    
    char* hostfile_data = NULL;
    size_t hostfile_size = 0;

    if(!mutka_map_file(host_signature_path, PROT_READ, &hostfile_data, &hostfile_size)) {
        goto out;
    }

    size_t offset = 0;

    memmove(server->host_signature.bytes, 
            hostfile_data,
            sizeof(server->host_signature.bytes));
    offset += sizeof(server->host_signature.bytes);


    memmove(server->host_mldsa87_publkey.bytes, 
            hostfile_data + offset,
            sizeof(server->host_mldsa87_publkey.bytes));
    //offset += sizeof(server->host_mldsa87_publkey.bytes);


    result = true;
    munmap(hostfile_data, hostfile_size);


out:
    return result;
}

struct mutka_server* mutka_create_server
(
    struct mutka_server_cfg config,
    const char* host_signature_path
){ 

    if((config.flags & MUTKA_SERVER_ENABLE_CAPTCHA)) {
        if(!ascii_captcha_init()) {
            mutka_set_errmsg("Failed to initialize captcha.");
            return NULL;
        }
    }

    struct mutka_server* server = malloc(sizeof *server);

    memset(server->host_mldsa87_publkey.bytes, 0, sizeof(server->host_mldsa87_publkey.bytes));
    memset(server->host_signature.bytes, 0, sizeof(server->host_signature.bytes));
    

    if(!p_mutka_server_read_host_signature(server, host_signature_path)) {
        // Host signature doesnt exist or it was not valid.
        // Ask to generate new one.

        if(!config.accept_host_signaturegen_callback()) {
            mutka_set_errmsg("Host signature generation was cancelled.");
            free(server);
            server = NULL;
            goto out;
        }

        if(!p_mutka_server_generate_host_signature(server, host_signature_path)) {
            mutka_set_errmsg("Failed to generate host signature.");
            free(server);
            server = NULL;
            goto out;
        }
    }


    server->config = config;
    server->socket_fd = -1;
    server->socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(server->socket_fd < 0) {
        mutka_set_errmsg("Failed to open socket for server | %s", strerror(errno));
        free(server);
        server = NULL;
        goto out;
    }

    explicit_bzero(&server->socket_addr, sizeof(server->socket_addr));

    server->socket_addr.sin_family = AF_INET;
    server->socket_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server->socket_addr.sin_port = htons(config.port);

    if((config.flags & MUTKA_SERVER_REUSEADDR)) {
        socklen_t opt = 1;
        setsockopt(server->socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    }

    int bind_result = bind(
            server->socket_fd,
            (struct sockaddr*)&server->socket_addr,
            sizeof(server->socket_addr));

    if(bind_result != 0) {
        mutka_set_errmsg("Failed bind address to socket | %s", strerror(errno));
        close(server->socket_fd);
        free(server);
        server = NULL;
        goto out;
    }


    int listen_queue_hint = 6;
    int listen_result = listen(server->socket_fd, listen_queue_hint);

    if(listen_result != 0) {
        mutka_set_errmsg("Failed set socket into listen mode | %s", strerror(errno));
        close(server->socket_fd);
        free(server);
        server = NULL;
        goto out;
    }

    srand(time(NULL));

    mutka_inpacket_init(&server->inpacket);
    mutka_alloc_rpacket(&server->out_raw_packet, MUTKA_RAW_PACKET_DEFMEMSIZE);
    mutka_alloc_rpacket(&server->inpacket.raw_packet, MUTKA_RAW_PACKET_DEFMEMSIZE);

    server->clients = malloc(config.max_clients * sizeof *server->clients);
    server->num_clients = 0;

    pthread_mutex_init(&server->mutex, NULL);

    pthread_create(&global.acceptor_thread, NULL, mutka_server_acceptor_thread_func, server);
    pthread_create(&global.recv_thread,     NULL, mutka_server_recvdata_thread_func, server);


out:
    return server;
}



void mutka_close_server(struct mutka_server* server) {
    if(!server) {
        return;
    }

    pthread_cancel(global.acceptor_thread);
    pthread_cancel(global.recv_thread);

    pthread_join(global.acceptor_thread, NULL);
    pthread_join(global.recv_thread, NULL);

    for(uint32_t i = 0; i < server->num_clients; i++) {
        mutka_disconnect(&server->clients[i]);
    }

    mutka_free_rpacket(&server->out_raw_packet);
    mutka_free_rpacket(&server->inpacket.raw_packet);
    mutka_free_packet(&server->inpacket);

    close(server->socket_fd);
    free(server);
}




void mutka_server_remove_client(struct mutka_server* server, struct mutka_client* client) {
    p_lock_server_mutex_ifneed(server);

    if(server->num_clients == 0) {
        mutka_set_errmsg("Trying to remove client(socket_fd = %i, uid = %i) from empty array.",
                client->socket_fd, client->uid);
        p_unlock_server_mutex_ifneed(server);
        return;
    }

    int remove_index = -1;

    for(uint32_t i = 0; i < server->num_clients; i++) {
        if(server->clients[i].socket_fd == client->socket_fd) {
            remove_index = i;
            break;
        }
    }
   
    if(remove_index >= 0) {
        mutka_disconnect(&server->clients[remove_index]);

        // Shift remaining clients from right to left.
        for(uint32_t i = remove_index; i < server->num_clients-1; i++) {
            server->clients[i] = server->clients[i+1];
        }

        server->num_clients--;
    }
    else {
        mutka_set_errmsg("Cant remove client, it doesnt exist. (socket_fd = %i, uid = %i)",
                client->socket_fd, client->uid);
    }

    p_unlock_server_mutex_ifneed(server);
}

static void p_mutka_server_make_client_uid(struct mutka_server* server, struct mutka_client* client) {
    bool client_has_unique_id = true;
    while(true) {
        for(uint32_t i = 0; i < server->num_clients; i++) {
            if(server->clients[i].uid == client->uid) {
                client_has_unique_id = false;
                break;
            }
        }
        if(client_has_unique_id) {
            break;
        }

        // Try again.
        client->uid = rand();
    }
}


static void p_mutka_server_init_connected_client(struct mutka_server* server, struct mutka_client* client) {
    client->env = MUTKA_ENV_SERVER;
    client->uid = rand();
    client->flags = 0;

    p_mutka_server_make_client_uid(server, client);

}

static void p_mutka_server_handle_client_connect(struct mutka_server* server, struct mutka_client* client) {
   
    p_mutka_server_init_connected_client(server, client);

    // Lock mutex here or 'accept' in mutka_server_acceptor_thread_func
    // will keep server->mutex locked.
    pthread_mutex_lock(&server->mutex);
    
    
    struct mutka_client* new_client_ptr = &server->clients[server->num_clients];
    *new_client_ptr = *client;
    server->num_clients++;
  
    server->config.client_connected_callback(server, new_client_ptr);


    mutka_rpacket_prep(&server->out_raw_packet, MPACKET_HOST_SIGNATURE);
    
    mutka_rpacket_add_ent(&server->out_raw_packet,
            "host_signature",
            server->host_signature.bytes, sizeof(server->host_signature.bytes),
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&server->out_raw_packet,
            "host_publkey",
            server->host_mldsa87_publkey.bytes, sizeof(server->host_mldsa87_publkey.bytes),
            RPACKET_ENCODE);

    mutka_send_clear_rpacket(client->socket_fd, &server->out_raw_packet);
}

void* mutka_server_acceptor_thread_func(void* arg) {
    struct mutka_server* server = (struct mutka_server*)arg;
    while(1) {

        pthread_mutex_lock(&server->mutex);
        if(server->num_clients+1 >= server->config.max_clients) {
            pthread_mutex_unlock(&server->mutex);

            // Server is full.
            mutka_sleep_ms(500);
            continue;
        }

        pthread_mutex_unlock(&server->mutex);


        struct mutka_client client;
        socklen_t socket_len = sizeof(client.socket_addr);
        client.socket_fd = accept(server->socket_fd, (struct sockaddr*)&client.socket_addr, &socket_len);

        if(client.socket_fd < 0) {
            mutka_set_errmsg("%s: accept() | %s", __func__, strerror(errno));
            continue;
        }

        p_mutka_server_handle_client_connect(server, &client);
        pthread_mutex_unlock(&server->mutex);
    }
    return NULL;
}


void* mutka_server_recvdata_thread_func(void* arg) {
    struct mutka_server* server = (struct mutka_server*)arg;

    while(1) {
        pthread_mutex_lock(&server->mutex);

        for(size_t i = 0; i < server->num_clients; i++) {
            struct mutka_client* client = &server->clients[i];
           
            int rd = mutka_recv_incoming_packet(&server->inpacket, client->socket_fd);
            if(rd == M_NEW_PACKET_AVAIL) {
                mutka_server_handle_packet(server, client);
            }
            else
            if(rd == M_LOST_CONNECTION) {
                server->config.client_disconnected_callback(server, client);
                mutka_server_remove_client(server, client);
                i--;
            }
        }

        pthread_mutex_unlock(&server->mutex);
        mutka_sleep_ms(100);
    }
    return NULL;
}


static void p_mutka_server_send_captcha_challenge(struct mutka_server* server, struct mutka_client* client) {
    printf("%s\n", __func__);

    /*
    memset(client->exp_captcha_answer, 0, sizeof(client->exp_captcha_answer));

    size_t captcha_buffer_len = 0;
    char* captcha_buffer = get_random_captcha_buffer
    (
        &captcha_buffer_len,
        client->exp_captcha_answer,
        sizeof(client->exp_captcha_answer) - 1
    );

    mutka_rpacket_prep(&server->out_raw_packet, MPACKET_CAPTCHA);
    mutka_rpacket_add_ent(&server->out_raw_packet,
            "captcha",
            captcha_buffer,
            captcha_buffer_len,
            RPACKET_ENCODE_NONE);

    mutka_send_encrypted_rpacket(client->socket_fd,
            &server->out_raw_packet,
            &client->metadata_shared_key);

    free(captcha_buffer);
    */
}
                
static void p_mutka_server_send_client_cipher_publkeys
(
    struct mutka_server* server,
    struct mutka_client* client,
    uint8_t* mlkem_wrappedkey,
    size_t   mlkem_wrappedkey_len,
    uint8_t* hkdf_salt_x25519,
    size_t   hkdf_salt_x25519_len,
    uint8_t* hkdf_salt_mlkem,
    size_t   hkdf_salt_mlkem_len
){

    // The client's keys are already generated from 
    // mutka_server_handle_packet() 'MPACKET_EXCHANGE_METADATA_KEYS'


    uint8_t publkey_combined_hash[SHA512_DIGEST_LENGTH * 2] = { 0};

    SHA512(client->mtdata_keys.x25519_publkey.bytes,
            sizeof(client->mtdata_keys.x25519_publkey.bytes),
            publkey_combined_hash);

    SHA512(mlkem_wrappedkey,
            mlkem_wrappedkey_len,
            publkey_combined_hash + SHA512_DIGEST_LENGTH);


    key_mldsa87_publ_t verifykey;
    signature_mldsa87_t signature;

    if(!mutka_openssl_MLDSA87_sign(MUTKA_VERSION_STR"(METADATAKEYS_FROM_SERVER)",
                &signature,
                &verifykey,
                (char*)publkey_combined_hash,
                sizeof(publkey_combined_hash))) {
        mutka_set_errmsg("%s: Failed to create signature.", __func__);
        return;
    }

    mutka_rpacket_prep(&server->out_raw_packet, MPACKET_EXCHANGE_METADATA_KEYS);
    mutka_rpacket_add_ent(&server->out_raw_packet,
            "x25519_public",
            client->mtdata_keys.x25519_publkey.bytes,
            sizeof(client->mtdata_keys.x25519_publkey.bytes),
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&server->out_raw_packet,
            "mlkem_wrapped",
            mlkem_wrappedkey,
            mlkem_wrappedkey_len,
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&server->out_raw_packet,
            "verify_with",
            verifykey.bytes,
            sizeof(verifykey.bytes),
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&server->out_raw_packet,
            "signature",
            signature.bytes,
            sizeof(signature.bytes),
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&server->out_raw_packet,
            "hkdf_salt_x25519",
            hkdf_salt_x25519,
            hkdf_salt_x25519_len,
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&server->out_raw_packet,
            "hkdf_salt_mlkem",
            hkdf_salt_mlkem,
            hkdf_salt_mlkem_len,
            RPACKET_ENCODE);

    mutka_send_clear_rpacket(client->socket_fd, &server->out_raw_packet);
}

void mutka_server_handle_packet(struct mutka_server* server, struct mutka_client* client) {
    // NOTE: server->mutex is locked here.

    printf("Handling packet, num_elements = %li\n", server->inpacket.num_elements);

    switch(server->inpacket.id) {

        /*
        case MPACKET_HOST_SIGNATURE_FAILED:
            mutka_set_errmsg("CLIENT %i COULD NOT VERIFY HOST SIGNATURE!", client->uid);
            return;

        case MPACKET_HOST_SIGNATURE_OK:
            printf("\033[32mClient %i verified host signature\033[0m\n", client->uid);
            
            client->flags |= MUTKA_SCFLG_MDKEYS_EXCHANGED;
            if((server->config.flags & MUTKA_SERVER_ENABLE_CAPTCHA)
            && !(client->flags & MUTKA_SCFLG_VERIFIED)) {
                p_mutka_server_send_captcha_challenge(server, client);
            }
            return;
        */

        case MPACKET_EXCHANGE_METADATA_KEYS:
            if(server->inpacket.num_elements != 4) {
                return;
            }
            {
                if(!mutka_generate_cipher_keys(&client->mtdata_keys)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: Failed to generate cipher keys for client.");
                    return;
                }

                struct mutka_packet_elem* peer_x25519_elem = &server->inpacket.elements[0];
                struct mutka_packet_elem* peer_mlkem_elem  = &server->inpacket.elements[1];
                struct mutka_packet_elem* verifykey_elem  = &server->inpacket.elements[2];
                struct mutka_packet_elem* signature_elem  = &server->inpacket.elements[3];

                key128bit_t           peer_x25519_publkey;
                key_mlkem1024_publ_t  peer_mlkem_publkey;

                key_mldsa87_publ_t    verifykey;
                signature_mldsa87_t   signature;

                if(!mutka_decode(peer_x25519_publkey.bytes, sizeof(peer_x25519_publkey.bytes),
                            peer_x25519_elem->data.bytes,
                            peer_x25519_elem->data.size)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: Failed to decode peer X25519 public key.");
                    return;
                }

                if(!mutka_decode(peer_mlkem_publkey.bytes, sizeof(peer_mlkem_publkey.bytes),
                            peer_mlkem_elem->data.bytes,
                            peer_mlkem_elem->data.size)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: Failed to decode peer ML-KEM-1024 public key.");
                    return;
                }

                if(!mutka_decode(verifykey.bytes, sizeof(verifykey.bytes),
                            verifykey_elem->data.bytes,
                            verifykey_elem->data.size)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: Failed to decode signature public key.");
                    return;
                }

                if(!mutka_decode(signature.bytes, sizeof(signature.bytes),
                            signature_elem->data.bytes,
                            signature_elem->data.size)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: Failed to decode signature.");
                    return;
                }

                // Get public keys combined hash to verify signature.
                uint8_t publkey_combined_hash[SHA512_DIGEST_LENGTH * 2] = { 0 };

                SHA512(peer_x25519_publkey.bytes, 
                        sizeof(peer_x25519_publkey.bytes),
                        publkey_combined_hash);
                
                SHA512(peer_mlkem_publkey.bytes, 
                        sizeof(peer_mlkem_publkey.bytes),
                        publkey_combined_hash + SHA512_DIGEST_LENGTH);
   

                if(!mutka_openssl_MLDSA87_verify(MUTKA_VERSION_STR"(METADATAKEYS_FROM_CLIENT)",
                            &signature,
                            &verifykey,
                            (char*)publkey_combined_hash,
                            sizeof(publkey_combined_hash))) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: Could not verify client's public cipher keys.");
                    return;
                }

                printf("\033[32mVerified client(%i) public cipher keys\033[0m\n", client->uid);


                uint8_t hkdf_salt_x25519[HKDF_SALT_LEN] = { 0 };
                RAND_bytes(hkdf_salt_x25519, sizeof(hkdf_salt_x25519));

                uint8_t hkdf_salt_mlkem[HKDF_SALT_LEN] = { 0 };
                RAND_bytes(hkdf_salt_mlkem, sizeof(hkdf_salt_mlkem));

                // Get X25519 shared key.
                if(!mutka_openssl_derive_shared_key(
                            &client->mtdata_keys.x25519_shared_key,
                            &client->mtdata_keys.x25519_privkey,
                            &peer_x25519_publkey,
                            hkdf_salt_x25519,
                            sizeof(hkdf_salt_x25519),
                            MUTKA_VERSION_STR"(METADATAKEYS_X25519_HKDF)")) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: Failed to derive shared X25519 key.");
                    return;
                }


                key128bit_t mlkem_shared_secret;
                uint8_t mlkem_wrappedkey[1024*2] = { 0 };
                size_t mlkem_wrappedkey_len = 0;

                // Get ML-KEM-1024 shared secret and wrapped key.
                if(!mutka_openssl_encaps(
                            mlkem_wrappedkey, 
                            sizeof(mlkem_wrappedkey),
                            &mlkem_wrappedkey_len,
                            &mlkem_shared_secret,
                            &peer_mlkem_publkey)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: Failed to encapsulate key.");
                    return;
                }

                // Pass mlkem shared secret through HKDF.
                if(!mutka_openssl_HKDF(
                            client->mtdata_keys.mlkem_shared_key.bytes,
                            sizeof(client->mtdata_keys.mlkem_shared_key.bytes),
                            mlkem_shared_secret.bytes,
                            sizeof(mlkem_shared_secret.bytes),
                            hkdf_salt_mlkem,
                            sizeof(hkdf_salt_mlkem),
                            MUTKA_VERSION_STR"(METADATAKEYS_MLKEM_HKDF)",
                            sizeof(client->mtdata_keys.mlkem_shared_key.bytes))) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: Failed to derive shared ML-KEM-1024 key.");
                    return;
                }

                p_mutka_server_send_client_cipher_publkeys(
                        server,
                        client,
                        mlkem_wrappedkey,
                        mlkem_wrappedkey_len,
                        hkdf_salt_x25519,
                        sizeof(hkdf_salt_x25519),
                        hkdf_salt_mlkem,
                        sizeof(hkdf_salt_mlkem));

            }
            return;
    }


    server->config.packet_received_callback(server, client);
}


