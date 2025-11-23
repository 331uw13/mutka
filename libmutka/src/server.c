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




static bool p_mutka_server_generate_hostkeys
(
    struct mutka_server* server,
    const char* hostkeys_path
){
    if(mutka_file_exists(hostkeys_path)) {
        remove(hostkeys_path);
    }

    if(!mutka_openssl_MLDSA87_keypair(&server->host_mldsa87_privkey, &server->host_mldsa87_publkey)) {
        return false;
    }


    uint8_t hostfile_data
        [ sizeof(server->host_mldsa87_privkey.bytes) +
          sizeof(server->host_mldsa87_publkey.bytes)] = { 0 };

    memmove(hostfile_data,
            server->host_mldsa87_privkey.bytes, 
            sizeof(server->host_mldsa87_privkey.bytes));

    memmove(hostfile_data + sizeof(server->host_mldsa87_privkey.bytes),
            server->host_mldsa87_publkey.bytes,
            sizeof(server->host_mldsa87_publkey.bytes));

    int fd = creat(hostkeys_path, S_IRUSR);
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

static bool p_mutka_server_read_hostkeys
(
    struct mutka_server* server,
    const char* hostkeys_path
){
    bool result = false;

    if(!mutka_file_exists(hostkeys_path)) {
        goto out;
    }

    if(mutka_file_size(hostkeys_path) !=
              sizeof(server->host_mldsa87_publkey.bytes) +
              sizeof(server->host_mldsa87_privkey.bytes)) {
        goto out;
    }
    
    char* hostfile_data = NULL;
    size_t hostfile_size = 0;

    if(!mutka_map_file(hostkeys_path, PROT_READ, &hostfile_data, &hostfile_size)) {
        goto out;
    }

    size_t offset = 0;

    // Read private key.
    memmove(server->host_mldsa87_privkey.bytes, 
            hostfile_data + offset,
            sizeof(server->host_mldsa87_privkey.bytes));

    offset += sizeof(server->host_mldsa87_privkey.bytes);

    // Read public key.
    memmove(server->host_mldsa87_publkey.bytes, 
            hostfile_data + offset,
            sizeof(server->host_mldsa87_publkey.bytes));


    result = true;
    munmap(hostfile_data, hostfile_size);


out:
    return result;
}

struct mutka_server* mutka_create_server
(
    struct mutka_server_cfg config,
    const char* hostkeys_path
){ 

    if((config.flags & MUTKA_SERVER_CAPTCHA_ENABLED)) {
        if(!ascii_captcha_init()) {
            mutka_set_errmsg("Failed to initialize captcha.");
            return NULL;
        }
    }

    struct mutka_server* server = malloc(sizeof *server);
    server->tmp_peer_info = NULL;
    server->tmp_peer_info = calloc(1, MUTKA_TMPPEERINFO_MAX);
    server->tmp_peer_info_len = 0;
    memset(server->host_mldsa87_privkey.bytes, 0, sizeof(server->host_mldsa87_privkey.bytes));
    memset(server->host_mldsa87_publkey.bytes, 0, sizeof(server->host_mldsa87_publkey.bytes));
    server->flags = 0; 

    if(!p_mutka_server_read_hostkeys(server, hostkeys_path)) {
        // Host signature doesnt exist or it was not valid.
        // Ask to generate new one.

        if(!config.accept_new_hostkeys_callback()) {
            mutka_set_errmsg("Host key generation was cancelled.");
            free(server);
            server = NULL;
            goto out;
        }

        if(!p_mutka_server_generate_hostkeys(server, hostkeys_path)) {
            mutka_set_errmsg("Failed to generate host keys");
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
    server->client_disconnect_queue = malloc(config.max_clients * sizeof *server->clients);
    server->num_clients_disconnecting = 0;

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

    if(server->tmp_peer_info) {
        free(server->tmp_peer_info);
        server->tmp_peer_info = NULL;
    }

    mutka_free_rpacket(&server->out_raw_packet);
    mutka_free_rpacket(&server->inpacket.raw_packet);
    mutka_free_packet(&server->inpacket);

    close(server->socket_fd);
    server->socket_fd = 0;
    
    free(server->clients);
    free(server->client_disconnect_queue);
    server->clients = NULL;
    server->client_disconnect_queue = NULL;

    free(server);
}

void mutka_server_remove_client
(
    struct mutka_server* server,
    int client_uid
){
    p_lock_server_mutex_ifneed(server);

    if(server->num_clients == 0) {
        p_unlock_server_mutex_ifneed(server);
        return;
    }

    int remove_index = -1;

    for(uint32_t i = 0; i < server->num_clients; i++) {
        if(server->clients[i].uid == client_uid) {
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
        mutka_set_errmsg("Cant remove client, it doesnt exist. (uid = %i)",
                client_uid);
    }

    p_unlock_server_mutex_ifneed(server);
}

static void p_mutka_server_process_disconnect_queue(struct mutka_server* server) {
    if((server->flags & MUTKA_SFLG_SENDING_CLIENT_MSGPUBLKEYS)) {
        return; // 'mutka_client.send_peerinfo_index' may go out of sync.
    }
    
    for(uint32_t i = 0; i < server->num_clients_disconnecting; i++) {
        mutka_server_remove_client(server, server->client_disconnect_queue[i]);
    }

    server->num_clients_disconnecting = 0;
}

static void p_mutka_server_client_disconnecting
(
    struct mutka_server* server,
    struct mutka_client* client
){

    if(server->num_clients_disconnecting+1 >= server->config.max_clients) {
        return;
    }
    
    // Check first if the client is already added to queue.
    for(uint32_t i = 0; i < server->num_clients_disconnecting; i++) {
        if(server->client_disconnect_queue[i] == client->uid) {
            //printf("%i Already disconnecting.\n", client->uid);
            return;
        }
    }

    printf("Disconnecting client: %i\n", client->uid);

    server->client_disconnect_queue
        [server->num_clients_disconnecting++] = client->uid;
}

static void p_mutka_server_make_client_uid
(
    struct mutka_server* server,
    struct mutka_client* client
){
    client->uid = rand();
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


static void p_mutka_server_init_connected_client
(
    struct mutka_server* server,
    struct mutka_client* client
){
    client->env = MUTKA_ENV_SERVER;
    client->uid = 0;
    client->flags = 0;
    client->captcha_retries_left = server->config.max_captcha_retries;        
    client->send_peerinfo_index = 0;
    p_mutka_server_make_client_uid(server, client);
}

static void p_mutka_server_send_captcha_challenge
(
    struct mutka_server* server,
    struct mutka_client* client
){
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

    printf("Expected captcha answer for %i: %s\n", client->uid, client->exp_captcha_answer);

    mutka_send_clear_rpacket(client->socket_fd, &server->out_raw_packet);
    free(captcha_buffer);
}

static void p_mutka_server_send_public_key
(
    struct mutka_server* server,
    struct mutka_client* client
){
    mutka_rpacket_prep(&server->out_raw_packet, MPACKET_HOST_PUBLIC_KEY);
    mutka_rpacket_add_ent(&server->out_raw_packet,
            "host_publkey",
            server->host_mldsa87_publkey.bytes, sizeof(server->host_mldsa87_publkey.bytes),
            RPACKET_ENCODE);

    mutka_send_clear_rpacket(client->socket_fd, &server->out_raw_packet);
}


static void p_mutka_server_handle_client_connect
(
    struct mutka_server* server,
    struct mutka_client* client
){  
    p_mutka_server_init_connected_client(server, client);
    
    struct mutka_client* new_client_ptr = &server->clients[server->num_clients];
    memmove(new_client_ptr, client, sizeof(*client));
    server->num_clients++;
 
    server->config.client_connected_callback(server, new_client_ptr);


    if((server->config.flags & MUTKA_SERVER_CAPTCHA_ENABLED)) {
        p_mutka_server_send_captcha_challenge(server, new_client_ptr);
    }
    else {
        p_mutka_server_send_public_key(server, new_client_ptr);
    }
}

void* mutka_server_acceptor_thread_func(void* arg) {
    struct mutka_server* server = (struct mutka_server*)arg;
    while(1) {
        pthread_mutex_lock(&server->mutex);
        
        if(server->num_clients+1 >= server->config.max_clients) {
            pthread_mutex_unlock(&server->mutex);

            // Server is full.
            mutka_sleep_ms(1000);
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

        // Lock server mutex here because accept()
        // would otherwise cause it to be locked until a connection arrives
        pthread_mutex_lock(&server->mutex);
 
        p_mutka_server_handle_client_connect(server, &client);
        
        pthread_mutex_unlock(&server->mutex);
    }
    return NULL;
}


void* mutka_server_recvdata_thread_func(void* arg) {
    struct mutka_server* server = (struct mutka_server*)arg;

    while(true) {
        pthread_mutex_lock(&server->mutex);

        for(size_t i = 0; i < server->num_clients; i++) {
            struct mutka_client* client = &server->clients[i];
           
            int rd = mutka_recv_incoming_packet(&server->inpacket, client->socket_fd);
            switch(rd) {
                case M_NEW_PACKET_AVAIL:
                    mutka_server_handle_packet(server, client);
                    break;

                case M_LOST_CONNECTION:
                    server->config.client_disconnected_callback(server, client);
                    p_mutka_server_client_disconnecting(server, client);
                    printf("%s: M_LOST_CONNECTION\n", __func__);
                    break;

                case M_ENCRYPTED_RPACKET:
                    if(mutka_parse_encrypted_rpacket(
                                &server->inpacket,
                                &server->inpacket.raw_packet,
                                &client->mtdata_keys.hshared_key)) {
                        mutka_server_handle_packet(server, client);
                    }
                    break;
            }
        }

        p_mutka_server_process_disconnect_queue(server);

        pthread_mutex_unlock(&server->mutex);
        mutka_sleep_ms(100);
    }
    return NULL;
}


                
static void p_mutka_server_send_client_cipher_publkeys
(
    struct mutka_server* server,
    struct mutka_client* client,
    key_mlkem1024_cipher_t* mlkem_cipher,
    uint8_t* hkdf_salt,
    size_t   hkdf_salt_len
){

    // The client's keys are already generated from 
    // mutka_server_handle_packet() 'MPACKET_EXCHANGE_METADATA_KEYS'

    // Combine server side client's keys hash
    // and create signature from that.
    uint8_t combined_publkey_hash[SHA512_DIGEST_LENGTH * 2] = { 0 };

    SHA512(client->mtdata_keys.x25519_publkey.bytes,
            sizeof(client->mtdata_keys.x25519_publkey.bytes),
            combined_publkey_hash);

    SHA512(mlkem_cipher->bytes,
            sizeof(mlkem_cipher->bytes),
            combined_publkey_hash + SHA512_DIGEST_LENGTH);

    signature_mldsa87_t signature;

    if(!mutka_openssl_MLDSA87_sign(
                MUTKA_VERSION_STR"(METADATAKEYS_SIGN_FROM_SERVER)",
                &signature,
                &server->host_mldsa87_privkey,
                combined_publkey_hash,
                sizeof(combined_publkey_hash))) {
        mutka_set_errmsg("%s: Failed to sign server side client's metadata keys.");
        return;
    }

    mutka_rpacket_prep(&server->out_raw_packet, MPACKET_EXCHANGE_METADATA_KEYS);
    mutka_rpacket_add_ent(&server->out_raw_packet,
            "x25519_public",
            client->mtdata_keys.x25519_publkey.bytes,
            sizeof(client->mtdata_keys.x25519_publkey.bytes),
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&server->out_raw_packet,
            "mlkem_cipher",
            mlkem_cipher->bytes,
            sizeof(mlkem_cipher->bytes),
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&server->out_raw_packet,
            "signature",
            signature.bytes,
            sizeof(signature.bytes),
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&server->out_raw_packet,
            "hkdf_salt",
            hkdf_salt,
            hkdf_salt_len,
            RPACKET_ENCODE);

    client->flags |= MUTKA_SCFLG_MTDATAKEYS_EXCHANGED;
    mutka_send_clear_rpacket(client->socket_fd, &server->out_raw_packet);
}

static bool p_client_has_confirmed_captcha
(
    struct mutka_server* server,
    struct mutka_client* client
){
    if(!(server->config.flags & MUTKA_SERVER_CAPTCHA_ENABLED)) {
        return true;
    }

    printf("CAPTCHA Confirmed: %s\n", 
            (client->flags & MUTKA_SCFLG_CAPTCHA_COMPLETE) ? "Yes" : "No");
    return (client->flags & MUTKA_SCFLG_CAPTCHA_COMPLETE);
}

// Is client fully verified? Can they send messages.
static bool p_client_verified
(
    struct mutka_server* server,
    struct mutka_client* client
){
    if(!(client->flags & MUTKA_SCFLG_MTDATAKEYS_EXCHANGED)) {
        return false;
    }
    if(!p_client_has_confirmed_captcha(server, client)) {
        return false;
    }

    // TODO: Add server password check.

    return true;
}

            

static void send_test_packet(struct mutka_server* server, struct mutka_client* client) {

    char* buffer = "Something idk doesnt matter here.";

    mutka_rpacket_prep(&server->out_raw_packet, MPACKET_TEST);
    mutka_rpacket_add_ent(&server->out_raw_packet,
            "testing",
            buffer,
            strlen(buffer),
            RPACKET_ENCODE_NONE);

    mutka_send_encrypted_rpacket(
            client->socket_fd,
            &server->out_raw_packet,
            &client->mtdata_keys.hshared_key);
}



void mutka_server_handle_packet
(
    struct mutka_server* server,
    struct mutka_client* client
){
    // NOTE: server->mutex is locked here.

    switch(server->inpacket.id) {

        case MPACKET_GET_PEER_PUBLKEYS:
            if(!p_client_verified(server, client)) {
                return;
            }
            if(!(client->flags & MUTKA_SCFLG_HAS_MSGKEYS)) {
                // Dont allow clients who have not sent their msg public keys  
                // to get other client's msg public keys.
                return;
            }
            {
                memset(server->tmp_peer_info, 0, 
                        server->tmp_peer_info_len > 
                        MUTKA_TMPPEERINFO_MAX ? MUTKA_TMPPEERINFO_MAX : server->tmp_peer_info_len);
                server->tmp_peer_info_len = 0;

                
                if(client->send_peerinfo_index >= server->config.max_clients) {
                    return;
                }


                server->flags |= MUTKA_SFLG_SENDING_CLIENT_MSGPUBLKEYS;
                bool is_last_peer = (client->send_peerinfo_index+1 >= server->num_clients);
               
                struct mutka_client* peer = &server->clients[client->send_peerinfo_index];
                mutka_rpacket_prep(&server->out_raw_packet, MPACKET_GET_PEER_PUBLKEYS);

                //printf("%i peerinfo_index = %i\n", client->uid, client->send_peerinfo_index);

                mutka_rpacket_add_ent(&server->out_raw_packet,
                        "ask_next",
                        &is_last_peer,
                        sizeof(is_last_peer),
                        RPACKET_ENCODE);

                mutka_rpacket_add_ent(&server->out_raw_packet,
                        "identity_publkey",
                        peer->msg_keys.identity_publkey.bytes,
                        sizeof(peer->msg_keys.identity_publkey.bytes),
                        RPACKET_ENCODE);

                mutka_rpacket_add_ent(&server->out_raw_packet,
                        "msg_key_signature",
                        peer->msg_keys.signature.bytes,
                        sizeof(peer->msg_keys.signature.bytes),
                        RPACKET_ENCODE);

                mutka_rpacket_add_ent(&server->out_raw_packet,
                        "msg_x25519_public",
                        peer->msg_keys.x25519_publkey.bytes,
                        sizeof(peer->msg_keys.x25519_publkey.bytes),
                        RPACKET_ENCODE);

                mutka_rpacket_add_ent(&server->out_raw_packet,
                        "msg_mlkem_public",
                        peer->msg_keys.mlkem_publkey.bytes,
                        sizeof(peer->msg_keys.mlkem_publkey.bytes),
                        RPACKET_ENCODE);

                mutka_send_encrypted_rpacket(
                        client->socket_fd,
                        &server->out_raw_packet,
                        &client->mtdata_keys.hshared_key);


                client->send_peerinfo_index++;
                if(client->send_peerinfo_index >= server->num_clients) {
                    client->send_peerinfo_index = 0;
                    server->flags &= ~MUTKA_SFLG_SENDING_CLIENT_MSGPUBLKEYS;
                    
                    printf("UNSET ~MUTKA_SFLG_SENDING_CLIENT_MSGPUBLKEYS\n");
                    // ... Ok cool but what about if the client dont respond.
                    //     All disconnects will hang.
                    // FIXME ^^^
                }
            }
            return;

        case MPACKET_DEPOSIT_PUBLIC_MSGKEYS:
            if(server->inpacket.num_elements != 4) {
                return;
            }
            if(!p_client_verified(server, client)) {
                return;
            }

            struct mutka_packet_elem* signature_elem = &server->inpacket.elements[0];
            struct mutka_packet_elem* public_identity_elem = &server->inpacket.elements[1];
            struct mutka_packet_elem* public_x25519_elem = &server->inpacket.elements[2];
            struct mutka_packet_elem* public_mlkem_elem = &server->inpacket.elements[3];


            if(!mutka_decode(client->msg_keys.identity_publkey.bytes,
                        sizeof(client->msg_keys.identity_publkey.bytes),
                        public_identity_elem->data.bytes,
                        public_identity_elem->data.size)) {
                mutka_set_errmsg("Failed to decode client(%i)'s public identity key.",
                        client->uid);
                return;
            }

            if(!mutka_decode(client->msg_keys.signature.bytes,
                        sizeof(client->msg_keys.signature.bytes),
                        signature_elem->data.bytes,
                        signature_elem->data.size)) {
                mutka_set_errmsg("Failed to decode client(%i)'s msg keys signature.");
                return;
            }
            if(!mutka_decode(client->msg_keys.x25519_publkey.bytes,
                        sizeof(client->msg_keys.x25519_publkey.bytes),
                        public_x25519_elem->data.bytes,
                        public_x25519_elem->data.size)) {
                mutka_set_errmsg("Failed to decode client(%i)'s public x25519 msg key.",
                        client->uid);
                return;
            }

            if(!mutka_decode(client->msg_keys.mlkem_publkey.bytes,
                        sizeof(client->msg_keys.mlkem_publkey.bytes),
                        public_mlkem_elem->data.bytes,
                        public_mlkem_elem->data.size)) {
                mutka_set_errmsg("Failed to decode client(%i)'s public ML-KEM-1024 msg key.",
                        client->uid);
                return;
            }

            client->flags |= MUTKA_SCFLG_HAS_MSGKEYS;
            return;

        case MPACKET_CAPTCHA:
            if(server->inpacket.num_elements != 1) {
                return;
            }
            if(p_client_has_confirmed_captcha(server, client)) {
                return;
            }
            {    
                struct mutka_str* answer = &server->inpacket.elements[0].data;

                if(mutka_str_lastbyte(answer) == '\n') {
                    // May be because client used 'read()' and forgot to remove the newline.
                    // It can be ignored.
                    mutka_str_pop_end(answer);
                }
                printf("Answer: '%s' %i\n", answer->bytes, answer->size);
                printf("Expected: '%s' %li\n", client->exp_captcha_answer, strlen(client->exp_captcha_answer));

                if(!mutka_strcmp(
                            client->exp_captcha_answer,
                            strlen(client->exp_captcha_answer),
                            answer->bytes,
                            answer->size)) {
                    client->captcha_retries_left--;
                    printf("%i captcha retries left: %i\n", client->uid, client->captcha_retries_left);
                    if(client->captcha_retries_left <= 0) {
                        //mutka_server_remove_client(server, client);
                        p_mutka_server_client_disconnecting(server, client);
                        return;
                    }
                    p_mutka_server_send_captcha_challenge(server, client);
                }
                else {
                    client->flags |= MUTKA_SCFLG_CAPTCHA_COMPLETE;
                    p_mutka_server_send_public_key(server, client);
                }
            }
            return;

        case MPACKET_METADATA_KEY_EXHCANGE_COMPLETE:
            if(!p_client_has_confirmed_captcha(server, client)) {
                return;
            }
            if(!(client->flags & MUTKA_SCFLG_MTDATAKEYS_EXCHANGED)) {
                return;
            }
           
            mutka_rpacket_prep(&server->out_raw_packet,
                    MPACKET_GENERAL_SERVER_INFO);

            mutka_rpacket_add_ent(&server->out_raw_packet,
                    "max_clients",
                    &server->config.max_clients,
                    sizeof(server->config.max_clients),
                    RPACKET_ENCODE);


            mutka_send_encrypted_rpacket(
                    client->socket_fd,
                    &server->out_raw_packet,
                    &client->mtdata_keys.hshared_key);
            printf("\033[32mMetadata key exchange with %i is complete.\033[0m\n", client->uid);
            return;

        case MPACKET_EXCHANGE_METADATA_KEYS:
            if(server->inpacket.num_elements != 2) {
                return;
            }
            if(!p_client_has_confirmed_captcha(server, client)) {
                return;
            }
            {
                if(!mutka_generate_cipher_keys(&client->mtdata_keys)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: "
                            "Failed to generate cipher keys for client.");
                    return;
                }

                struct mutka_packet_elem* peer_x25519_elem = &server->inpacket.elements[0];
                struct mutka_packet_elem* peer_mlkem_elem  = &server->inpacket.elements[1];

                key128bit_t           peer_x25519_publkey;
                key_mlkem1024_publ_t  peer_mlkem_publkey;

                if(!mutka_decode(peer_x25519_publkey.bytes, sizeof(peer_x25519_publkey.bytes),
                            peer_x25519_elem->data.bytes,
                            peer_x25519_elem->data.size)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: "
                            "Failed to decode peer X25519 public key.");
                    return;
                }

                if(!mutka_decode(peer_mlkem_publkey.bytes, sizeof(peer_mlkem_publkey.bytes),
                            peer_mlkem_elem->data.bytes,
                            peer_mlkem_elem->data.size)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: "
                            "Failed to decode peer ML-KEM-1024 public key.");
                    return;
                }

                uint8_t hkdf_salt[HKDF_SALT_LEN] = { 0 };
                RAND_bytes(hkdf_salt, sizeof(hkdf_salt));

                key_mlkem1024_cipher_t mlkem_cipher;
                const char* hkdf_info = MUTKA_VERSION_STR"(METADATAKEYS_HYBRIDKEY_HKDF)";

                if(!mutka_hybrid_kem_encaps(
                            &client->mtdata_keys.hshared_key,
                            &mlkem_cipher,
                            &client->mtdata_keys,
                            &peer_x25519_publkey,
                            &peer_mlkem_publkey,
                            hkdf_salt,
                            hkdf_info
                            )) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: "
                            "mutka_hybrid_kem_encaps() failed!");
                    return;
                }

                p_mutka_server_send_client_cipher_publkeys(
                        server,
                        client,
                        &mlkem_cipher,
                        hkdf_salt,
                        sizeof(hkdf_salt));
            }
            return;
    }


    server->config.packet_received_callback(server, client);
}


