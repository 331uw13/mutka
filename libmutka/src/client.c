#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#include "../include/client.h"
#include "../include/mutka.h"



static struct client_global {
    
    pthread_t recv_thread;

}
global;


void* mutka_client_recv_thread(void* arg);
void mutka_client_handle_packet(struct mutka_client* client);


#include <stdio.h>


static bool get_mutka_user_dir(struct mutka_client_cfg* config, struct mutka_str* path) {
    // TODO: handle null pointers.

    size_t cfgdir_len = strlen(config->mutka_cfgdir);
    size_t nickname_len = strlen(config->nickname);

    if(!nickname_len) {
        mutka_set_errmsg("Config doesnt contain nickname");
        return false;
    }

    if(cfgdir_len > 0) {
        mutka_str_move(path, config->mutka_cfgdir, cfgdir_len);

        if(mutka_str_lastbyte(path) != '/') {
            mutka_str_pushbyte(path, '/');
        }
    }
        
    if(!mutka_str_append(path, config->nickname, nickname_len)) {
        mutka_set_errmsg("Failed to append nickname to path.");
        return false;
    }

    if(mutka_str_lastbyte(path) != '/') {
        mutka_str_pushbyte(path, '/');
    }

    return true;
}


#define MUTKA_TRUSTED_KEY_SUFFIX ".public_key"
#define MUTKA_TRUSTED_PEERS_DIRNAME "trusted_peers"

bool get_mutka_user_trustedkey_path(struct mutka_str* path, struct mutka_client_cfg* config) {

    if(!get_mutka_user_dir(config, path)) {
        return false;
    }

    if(!mutka_str_append(path, 
                config->nickname,
                strlen(config->nickname))) {
        return false;
    }

    if(!mutka_str_append(path, 
                MUTKA_TRUSTED_KEY_SUFFIX, 
                strlen(MUTKA_TRUSTED_KEY_SUFFIX))) {
        return false;
    }

    return true;
}

bool get_mutka_trustedpeers_path(struct mutka_str* path, struct mutka_client_cfg* config) {

    if(!get_mutka_user_dir(config, path)) {
        return false;
    }

    if(!mutka_str_append(path, 
                MUTKA_TRUSTED_PEERS_DIRNAME,
                strlen(MUTKA_TRUSTED_PEERS_DIRNAME))) {
        return false;
    }

    return true;
}

bool mutka_cfg_trustedkey_exists(struct mutka_client_cfg* config) {
    
    struct mutka_str path;
    mutka_str_alloc(&path);

    if(!get_mutka_user_trustedkey_path(&path, config)) {
        mutka_str_free(&path);
        return false;
    }

    bool exists = (access(path.bytes, F_OK) == 0);

    mutka_str_free(&path);
    return exists;
}

bool mutka_cfg_generate_trustedkey(struct mutka_client_cfg* config) {

    /*
        Build path to the user's trusted keys directory.
        
        Example how the directory looks like:
        /home/user/.mutka/
        |- username123/
           |- username123.public_key
           |- username123.private_key (encrypted)
           |- trusted_peers/
              |- friend_A.public_key
              |- friend_B.public_key
    */


    struct mutka_keypair trusted_keys = mutka_init_keypair();

    if(!mutka_openssl_ED25519_keypair(&trusted_keys)) {
        return false;
    }

    struct mutka_str trusted_publkey_hexstr;
    mutka_str_alloc(&trusted_publkey_hexstr);
    mutka_bytes_to_hexstr(&trusted_keys.public_key, &trusted_publkey_hexstr);

    //printf("%s\n", trusted_publkey_hexstr.bytes);




    mutka_str_free(&trusted_publkey_hexstr);
    mutka_free_keypair(&trusted_keys);
    return true;
}


struct mutka_client* mutka_connect(struct mutka_client_cfg* config) {
    struct mutka_client* client = malloc(sizeof *client);
    client->env = MUTKA_ENV_NULL;

    client->socket_fd = -1;
    client->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(client->socket_fd < 0) {
        mutka_set_errmsg("Failed to open socket. %s", strerror(errno));
        free(client);
        client = NULL;
        goto out;
    }

    client->socket_addr.sin_family = AF_INET;
    client->socket_addr.sin_port = htons(config->port);

    inet_pton(AF_INET, config->host, &client->socket_addr.sin_addr);


    int connect_result = connect(
            client->socket_fd,
            (struct sockaddr*)&client->socket_addr,
            sizeof(client->socket_addr));

    if(connect_result != 0) {
        mutka_set_errmsg("Connection failed to (%s:%i) | %s", 
                config->host, config->port, strerror(errno));
        close(client->socket_fd);
        free(client);
        client = NULL;
        goto out;
    }

    client->env = MUTKA_ENV_CLIENT;

    mutka_alloc_rpacket(&client->out_raw_packet, MUTKA_RAW_PACKET_DEFMEMSIZE);
    mutka_alloc_rpacket(&client->inpacket.raw_packet, MUTKA_RAW_PACKET_DEFMEMSIZE);

    client->handshake_complete = false;
    client->metadata_keys = mutka_init_keypair();

    mutka_str_alloc(&client->peer_metadata_publkey);
    mutka_openssl_X25519_keypair(&client->metadata_keys);

    // Create thread for receiving data.
    pthread_create(&global.recv_thread, NULL, mutka_client_recv_thread, client);
    
    // Initiate handshake by sending generated metadata public key.
    // see packet.h for more information about metadata keys.
    mutka_rpacket_prep(&client->out_raw_packet, MPACKET_HANDSHAKE);
    mutka_rpacket_add_ent(&client->out_raw_packet, 
            "metadata_publkey", 
            client->metadata_keys.public_key.bytes, 
            client->metadata_keys.public_key.size);

    mutka_send_rpacket(client->socket_fd, &client->out_raw_packet);


out:
    return client;
}


void mutka_disconnect(struct mutka_client* client) {

    if((client->env != MUTKA_ENV_CLIENT)
    && (client->env != MUTKA_ENV_SERVER)) {
        mutka_set_errmsg("The client which is trying to disconnect"
                " doesnt have valid environment");
        return;
    }

    // If called from client side. 
    // First the threads must be stopped or they 
    // may try to access the data after it was freed.
    if(client->env == MUTKA_ENV_CLIENT) {
        pthread_cancel(global.recv_thread);
        pthread_join(global.recv_thread, NULL);
    }

    if(client->socket_fd >= 0) {
        close(client->socket_fd);
        client->socket_fd = -1;
    }

    mutka_free_keypair(&client->metadata_keys);
    mutka_str_free(&client->peer_metadata_publkey);

    if(client->env == MUTKA_ENV_CLIENT) {
        mutka_free_rpacket(&client->out_raw_packet);
        mutka_free_packet(&client->inpacket);
        free(client);
    }
    
}

#include <stdio.h> // <- temp

void* mutka_client_recv_thread(void* arg) {
    struct mutka_client* client = (struct mutka_client*)arg;
    while(true) {
        pthread_mutex_lock(&client->mutex);

        int rd = mutka_recv_incoming_packet(&client->inpacket, client->socket_fd);
        if(rd == M_NEW_PACKET_AVAIL) {
            mutka_client_handle_packet(client);
        }
        else
        if(rd == M_LOST_CONNECTION) {
            printf("lost connection TODO: handle this\n");
        }

        pthread_mutex_unlock(&client->mutex);
        mutka_sleep_ms(1); // Small delay to limit CPU usage.
    }
    return NULL;
}

void mutka_client_handle_packet(struct mutka_client* client) {
    // NOTE: client->mutex is locked here.

    // Check for internal packets first.
    switch(client->inpacket.id) {
        case MPACKET_HANDSHAKE:
            if(client->handshake_complete) {
                mutka_set_errmsg("Handshake has already been complete.");
                return;
            }

            if(client->inpacket.num_elements == 0) {
                mutka_set_errmsg("Failed to receive handshake packet.");
                return;
            }

            mutka_str_move(
                    &client->peer_metadata_publkey, 
                    client->inpacket.elements[0].data.bytes,
                    client->inpacket.elements[0].data.size);

            client->handshake_complete = true;
            return;
    }

    client->packet_received_callback(client);
}


