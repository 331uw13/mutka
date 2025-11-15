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
    
    // The signature file contains the public key too.

    char* sigfile_data = NULL;
    size_t sigfile_size = 0;






unmap_and_out:

    munmap(sigfile, sigfile_size);

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
    }

    /*
    if(!p_mutka_server_read_host_keys(server, publkey_path, privkey_path)) {
       
        if(!config.accept_host_keygen_callback()) {
            mutka_set_errmsg("Host ed25519 key generation was cancelled.");
            free(server);
            server = NULL;
            goto out;
        }

        // Host keys dont exists or they are not valid
        // Try to generate and save new pair.
        if(!p_mutka_server_generate_host_keys(server, publkey_path, privkey_path)) {
            mutka_set_errmsg("Failed to generate new host keys");
            free(server);
            server = NULL;
            goto out;
        }
    }
    */

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

static void mutka_server_handle_client_connect(struct mutka_server* server, struct mutka_client* client) {
    client->env = MUTKA_ENV_SERVER;
    client->uid = rand();
    client->flags = 0;

    p_mutka_server_make_client_uid(server, client);

    MUTKA_CLEAR_KEY(client->metadata_privkey);
    MUTKA_CLEAR_KEY(client->metadata_publkey);
    MUTKA_CLEAR_KEY(client->peer_metadata_publkey);

    // Lock mutex here or 'accept' in mutka_server_acceptor_thread_func
    // will keep server->mutex locked.
    pthread_mutex_lock(&server->mutex);
    
    
    struct mutka_client* new_client_ptr = &server->clients[server->num_clients];
    *new_client_ptr = *client;
    server->num_clients++;
  
    server->config.client_connected_callback(server, new_client_ptr);


    printf("%s: TODO: SEND HOST SIGNATURE and MLDSA87 PUBLIC KEY TO CLIENT\n", __func__);

    /*
    // Send host public key for client.
    mutka_rpacket_prep(&server->out_raw_packet, MPACKET_HOST_PUBLIC_KEY);
    mutka_rpacket_add_ent(&server->out_raw_packet, 
            "host_public_key",
            server->host_mldsa87_publkey.bytes,
            sizeof(server->host_ed25519_publkey.bytes),
            RPACKET_ENCODE);
    mutka_dump_key(&server->host_ed25519_publkey, "host public key");
    i*/

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

        mutka_server_handle_client_connect(server, &client);
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

}

void mutka_server_handle_packet(struct mutka_server* server, struct mutka_client* client) {
    // NOTE: server->mutex is locked here.

    printf("Handling packet, num_elements = %li\n", server->inpacket.num_elements);

    switch(server->inpacket.id) {

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

        case MPACKET_EXCHANGE_METADATA_KEYS:
            if(server->inpacket.num_elements != 2) {
                return;
            }
            {
                signature_t signature;
                
                struct mutka_packet_elem* key_elem = &server->inpacket.elements[0];
                struct mutka_packet_elem* nonce_elem = &server->inpacket.elements[1];
                uint8_t client_nonce[16] = { 0 };

                if(!mutka_decode(
                            client->peer_metadata_publkey.bytes,
                            sizeof(client->peer_metadata_publkey.bytes),
                            key_elem->data.bytes,
                            key_elem->data.size)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: Failed to decode metadata public key.");
                    return;
                }

                if(!mutka_decode(
                            client_nonce,
                            sizeof(client_nonce),
                            nonce_elem->data.bytes,
                            nonce_elem->data.size)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: Failed to decode client nonce.");
                    return;
                }

                /*
                if(!mutka_openssl_ED25519_sign(&signature,
                            &server->host_ed25519_privkey,
                            (char*)client_nonce,
                            sizeof(client_nonce))) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: Failed create signature.", __func__);
                    return;
                }
                */

                mutka_dump_sig(&signature, "signature");

                // Generate X25519 keypair for the client which will be stored on the server.
                // See packet.h for more information about metadata keys.
                mutka_openssl_X25519_keypair(&client->metadata_privkey, &client->metadata_publkey);


                mutka_dump_key(&client->metadata_publkey, "client metadata publkey (SERVER SIDE)");
                mutka_dump_key(&client->peer_metadata_publkey, "peer metadata publkey");


                uint8_t hkdf_salt[HKDF_SALT_LEN] = { 0 };
                char hkdf_info[64] = { 0 };
                if(!mutka_get_hkdf_info(hkdf_info, sizeof(hkdf_info), HKDFCTX_METADATA_KEYS)) {
                    return;
                }

                RAND_bytes(hkdf_salt, sizeof(hkdf_salt));

                if(!mutka_openssl_derive_shared_key(
                            &client->metadata_shared_key,
                            &client->metadata_privkey,
                            &client->peer_metadata_publkey,
                            hkdf_salt,
                            sizeof(hkdf_salt),
                            hkdf_info)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: Failed to derive shared metadata key for client %i",
                            client->uid);
                    return;
                }

                mutka_dump_key(&client->metadata_shared_key, "metadata_shared_key");

                // Derive shared metadata key.

                mutka_rpacket_prep(&server->out_raw_packet, MPACKET_EXCHANGE_METADATA_KEYS);
                mutka_rpacket_add_ent(&server->out_raw_packet,
                        "metadata_publkey", 
                        client->metadata_publkey.bytes,
                        sizeof(client->metadata_publkey.bytes),
                        RPACKET_ENCODE);

                mutka_rpacket_add_ent(&server->out_raw_packet,
                        "signature",
                        signature.bytes,
                        sizeof(signature.bytes),
                        RPACKET_ENCODE);

                mutka_rpacket_add_ent(&server->out_raw_packet,
                        "hkdf_salt",
                        hkdf_salt,
                        sizeof(hkdf_salt),
                        RPACKET_ENCODE);

                mutka_send_clear_rpacket(client->socket_fd, &server->out_raw_packet);
            }
            return;
    }


    server->config.packet_received_callback(server, client);
}


