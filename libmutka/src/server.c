#include <stdlib.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/stat.h>

#include "../include/server.h"
#include "../include/mutka.h"


// DONT CHANGE AFTER SERVER HAS GENERATED ITS HOST KEYS.
// Used to identify the key file.
#define HOST_ED25519_PRIVKEY_HEADER_TAG "HOST_PRIVKEY"
#define HOST_ED25519_PUBLKEY_HEADER_TAG "HOST_PUBLKEY"


static struct server_global {
    pthread_t acceptor_thread;
    pthread_t recv_thread;
}
global;


#include <stdio.h>

static void lock_server_mutex_ifneed(struct mutka_server* server) {
    pthread_t self = pthread_self();
    if(self != global.recv_thread) {
        pthread_mutex_lock(&server->mutex);
    }
}

static void unlock_server_mutex_ifneed(struct mutka_server* server) {
    pthread_t self = pthread_self();
    if(self != global.recv_thread) {
        pthread_mutex_unlock(&server->mutex);
    }
}

void* mutka_server_acceptor_thread_func(void* arg);
void* mutka_server_recvdata_thread_func(void* arg);
void mutka_server_handle_packet(struct mutka_server* server, struct mutka_client* client);



static bool mutka_server_save_host_key(const char* path, const char* header_tag, struct mutka_str* key) {
    mutka_file_clear(path);

    if(!mutka_file_append(path, (char*)header_tag, strlen(header_tag))) {
        mutka_set_errmsg("Failed to save \"%s\" (File header tag) | %s", 
                header_tag, strerror(errno));
        return false;
    }
    if(!mutka_file_append(path, key->bytes, key->size)) { 
        mutka_set_errmsg("Failed to save \"%s\" | %s",
                header_tag, strerror(errno));
        return false;
    }
    return true;
}

static bool mutka_server_validate_keyfile(char* file_data, 
        const char* expected_header_tag, size_t header_tag_len) {
    for(size_t i = 0; i < header_tag_len; i++) {
        if(file_data[i] != expected_header_tag[i]) {
            mutka_set_errmsg("Host ed25519 key file header tag is changed or corrupted after it was created. "
                    "Expected \"%s\"", expected_header_tag);
            return false;
        }
    }
    return true;
}

static bool mutka_server_get_host_keys(struct mutka_server* server, const char* publkey_path, const char* privkey_path) {
    bool result = false;
    bool generate_new_keys = false;

    if(!mutka_file_exists(publkey_path)) {
        if(creat(publkey_path, S_IRUSR | S_IWUSR) < 0) {
            mutka_set_errmsg("Failed to create '%s' | %s", publkey_path, strerror(errno));
            goto out;
        }
        generate_new_keys = true;
    }
    if(!mutka_file_exists(privkey_path)) {
        if(creat(privkey_path, S_IRUSR | S_IWUSR) < 0) {
            mutka_set_errmsg("Failed to create '%s' | %s", privkey_path, strerror(errno));
            goto out;
        } 
        generate_new_keys = true;
    }


    char* publkey_file = NULL;
    size_t publkey_file_size = 0;

    char* privkey_file = NULL;
    size_t privkey_file_size = 0;

    if(!mutka_map_file(publkey_path, &publkey_file, &publkey_file_size)) {
        goto out;
    }

    if(!mutka_map_file(privkey_path, &privkey_file, &privkey_file_size)) {
        goto out;
    }
   
    server->host_ed25519 = mutka_init_keypair();

    const size_t publkey_file_header_len = strlen(HOST_ED25519_PUBLKEY_HEADER_TAG);
    const size_t privkey_file_header_len = strlen(HOST_ED25519_PRIVKEY_HEADER_TAG);

    if((publkey_file_size < ED25519_KEYLEN + publkey_file_header_len)
    || (privkey_file_size < ED25519_KEYLEN + privkey_file_header_len)) {
        generate_new_keys = true;
    }

    if(generate_new_keys) { 
        if(!mutka_openssl_ED25519_keypair(&server->host_ed25519)) {
            goto out;
        }

        if(!mutka_server_save_host_key(publkey_path, 
                    HOST_ED25519_PUBLKEY_HEADER_TAG, &server->host_ed25519.public_key)) {        
            mutka_free_keypair(&server->host_ed25519);
            goto out;
        }

        if(!mutka_server_save_host_key(privkey_path, 
                    HOST_ED25519_PRIVKEY_HEADER_TAG, &server->host_ed25519.private_key)) {        
            goto out;
        }

        // Set only readable by user who created the files.
        chmod(publkey_path, S_IRUSR);
        chmod(privkey_path, S_IRUSR);
    }
    else {
        // Read existing keys.

        if(!mutka_server_validate_keyfile(publkey_file, 
                    HOST_ED25519_PUBLKEY_HEADER_TAG, publkey_file_header_len)) {
            goto out;
        }

        if(!mutka_server_validate_keyfile(privkey_file, 
                    HOST_ED25519_PRIVKEY_HEADER_TAG, privkey_file_header_len)) {
            goto out;
        }


        mutka_str_move(&server->host_ed25519.public_key,
                publkey_file + publkey_file_header_len,
                publkey_file_size - publkey_file_header_len);

        mutka_str_move(&server->host_ed25519.private_key,
                privkey_file + privkey_file_header_len,
                privkey_file_size - privkey_file_header_len);
    }

    result = true;


out:

    if(!result) {
        mutka_free_keypair(&server->host_ed25519);
    }

    printf("%s: OK\n", __func__);

    return true;
}

struct mutka_server* mutka_create_server
(
    struct mutka_server_cfg config,
    const char* publkey_path,
    const char* privkey_path
){ 
    struct mutka_server* server = malloc(sizeof *server);
    
    if(!mutka_server_get_host_keys(server, publkey_path, privkey_path)) {
        free(server);
        server = NULL;
        goto out;
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
    server->socket_addr.sin_addr.s_addr = htonl(INADDR_ANY); // TODO: Allow host to be configured.
    server->socket_addr.sin_port = htons(config.port);

    if((config.flags & MUTKA_S_FLG_REUSEADDR)) {
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

    server->inpacket.elements = NULL;
    server->inpacket.num_elements = 0;
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

    mutka_free_keypair(&server->host_ed25519);

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
    lock_server_mutex_ifneed(server);

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
    }

    unlock_server_mutex_ifneed(server);
}

static void mutka_server_make_client_uid(struct mutka_server* server, struct mutka_client* client) {
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

    mutka_server_make_client_uid(server, client);

    client->metadata_keys = mutka_init_keypair();
    mutka_str_alloc(&client->peer_metadata_publkey);

    // Lock mutex here or 'accept' in mutka_server_acceptor_thread_func
    // will keep server->mutex locked.
    pthread_mutex_lock(&server->mutex);
    
    
    struct mutka_client* new_client_ptr = &server->clients[server->num_clients];
    *new_client_ptr = *client;
    server->num_clients++;
  
    server->config.client_connected_callback(server, new_client_ptr);
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
            printf("Failed to accept client. %s\n", strerror(errno));
            // TODO
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



void mutka_server_handle_packet(struct mutka_server* server, struct mutka_client* client) {
    // NOTE: server->mutex is locked here.

    printf("Handling MPACKET_HANDSHAKE, elements: %i\n", server->inpacket.num_elements);

    switch(server->inpacket.id) {
        case MPACKET_EXCHANGE_METADATA_KEYS:
            if(server->inpacket.num_elements == 0) {
                return;
            }


            // First save the received peer metadata public key.
            struct mutka_packet_elem* key_elem = &server->inpacket.elements[0];
            mutka_openssl_BASE64_decode(&client->peer_metadata_publkey,
                    key_elem->data.bytes,
                    key_elem->data.size);

            // Generate X25519 keypair for the client which will be stored on the server.
            // See packet.h for more information about metadata keys.
            mutka_openssl_X25519_keypair(&client->metadata_keys);
            
            mutka_dump_strbytes(&client->peer_metadata_publkey, "peer metadata publkey");
            mutka_dump_strbytes(&client->metadata_keys.public_key, "client(server side) metadata publkey");


            mutka_rpacket_prep(&server->out_raw_packet, MPACKET_EXCHANGE_METADATA_KEYS);
            mutka_rpacket_add_ent(&server->out_raw_packet,
                    "metadata_publkey", 
                    client->metadata_keys.public_key.bytes,
                    client->metadata_keys.public_key.size,
                    RPACKET_ENCODE_BASE64);
            
            mutka_send_rpacket(client->socket_fd, &server->out_raw_packet);
            return;
    }


    server->config.packet_received_callback(server, client);
}


