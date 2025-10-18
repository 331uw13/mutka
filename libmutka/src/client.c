#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include "../include/client.h"
#include "../include/mutka.h"



static struct client_global {
    
    pthread_t recv_thread;

}
global;


void* mutka_client_recv_thread(void* arg);
void mutka_client_handle_packet(struct mutka_client* client);


#include <stdio.h>

#define MUTKA_TRUSTED_PUBLKEY_SUFFIX ".public_key"
#define MUTKA_TRUSTED_PRIVKEY_SUFFIX ".private_key"
#define MUTKA_TRUSTED_PEERS_DIRNAME "trusted_peers"
#define MUTKA_DEF_CFGDIR_NAME ".mutka/" // So the default config directory would be /home/user/.mutka/


bool mutka_validate_client_cfg(struct mutka_client_cfg* config) {
    bool result = false;

    size_t nickname_length = strlen(config->nickname);
    if(nickname_length == 0) {
        mutka_set_errmsg("Nickname is required.");
        return false;
    }

    // TODO: Move the operations to their own functions for readability.

    // Config directory is copied to 'struct mutka_str' 
    // for making changes to it easier.
    // trusted_peers_dir, trusted_privkey_path and trusted_publkey_path
    // are constructed from the mutka_cfgdir.

    /*
        Example how the directory looks like:
        /home/user/.mutka/
        '- username123/
           |- username123.public_key
           |- username123.private_key (encrypted)
           '- trusted_peers/
              |- friend_A.public_key
              '- friend_B.public_key
    */

    struct mutka_str tmpdir;
    mutka_str_alloc(&tmpdir);


    if(config->use_default_cfgdir) {

        struct passwd* pw = getpwuid(getuid());
        if(!pw) {
            mutka_set_errmsg("Failed to get user passwd "
                    "file entry (for home directory) | %s", strerror(errno));
            goto out;
        }

        size_t pwdir_len = strlen(pw->pw_dir);
        if(pwdir_len == 0) {
            mutka_set_errmsg("User doesnt have home directory? "
                    "(struct passwd* pw, pw->pw_dir length is zero)");
            goto out;
        }

        mutka_str_move(&tmpdir, pw->pw_dir, pwdir_len);
        
    }
    else {
        // User has chosen a config directory.
        
        size_t user_cfgdir_len = strlen(config->mutka_cfgdir);
        if(user_cfgdir_len == 0) {
            mutka_set_errmsg("When config.use_default_cfgdir is set to 'false', "
                    "config.mutka_cfgdir cant be empty.");
            goto out;
        }

        mutka_str_move(&tmpdir, config->mutka_cfgdir, user_cfgdir_len);
    }

    if(mutka_str_lastbyte(&tmpdir) != '/') {
        mutka_str_pushbyte(&tmpdir, '/');
    }

    if(config->use_default_cfgdir) {
        mutka_str_append(&tmpdir, MUTKA_DEF_CFGDIR_NAME, strlen(MUTKA_DEF_CFGDIR_NAME));
    }

    // Different nicknames can have different configurations.
    mutka_str_append(&tmpdir, config->nickname, nickname_length);

    if(mutka_str_lastbyte(&tmpdir) != '/') {
        mutka_str_pushbyte(&tmpdir, '/');
    }
    

    // Save validated config directory.

    if(tmpdir.size >= sizeof(config->mutka_cfgdir)) {
        mutka_set_errmsg("Config directory path is too long");
        goto out;
    }
    memset(config->mutka_cfgdir, 0, sizeof(config->mutka_cfgdir));
    memmove(config->mutka_cfgdir, tmpdir.bytes, tmpdir.size);

    // This will be needed later.
    const size_t cfgdir_length = strlen(config->mutka_cfgdir);


    // Construct the trusted_peers_dir.
    mutka_str_append(&tmpdir, 
            MUTKA_TRUSTED_PEERS_DIRNAME,
            strlen(MUTKA_TRUSTED_PEERS_DIRNAME));

    if(tmpdir.size >= sizeof(config->trusted_peers_dir)) {
        mutka_set_errmsg("Trusted peers directory path is too long");
        goto out;
    }

    memmove(config->trusted_peers_dir, tmpdir.bytes, tmpdir.size);


    // Construct trusted_privkey_path.

    // Go back to config directory.
    mutka_str_move(&tmpdir, config->mutka_cfgdir, cfgdir_length);
    
    mutka_str_append(&tmpdir, config->nickname, nickname_length);
    mutka_str_append(&tmpdir, 
            MUTKA_TRUSTED_PRIVKEY_SUFFIX,
            strlen(MUTKA_TRUSTED_PRIVKEY_SUFFIX));

    if(tmpdir.size >= sizeof(config->trusted_privkey_path)) {
        mutka_set_errmsg("Trusted private key path is too long");
        goto out;
    }
   
    memmove(config->trusted_privkey_path, tmpdir.bytes, tmpdir.size);

    // Construct trusted_publkey_path.

    // Go back to config directory.
    mutka_str_move(&tmpdir, config->mutka_cfgdir, cfgdir_length);
    
    mutka_str_append(&tmpdir, config->nickname, nickname_length);
    mutka_str_append(&tmpdir, 
            MUTKA_TRUSTED_PUBLKEY_SUFFIX,
            strlen(MUTKA_TRUSTED_PUBLKEY_SUFFIX));

    if(tmpdir.size >= sizeof(config->trusted_publkey_path)) {
        mutka_set_errmsg("Trusted public key path is too long");
        goto out;
    }

    memmove(config->trusted_publkey_path, tmpdir.bytes, tmpdir.size);

    printf("%s\n", config->mutka_cfgdir);
    printf("%s\n", config->trusted_peers_dir);
    printf("%s\n", config->trusted_privkey_path);
    printf("%s\n", config->trusted_publkey_path);

    result = true;

out:
    mutka_str_free(&tmpdir);

    return result;
}

bool mutka_cfg_trustedkeys_exists(struct mutka_client_cfg* config) {
    bool publkey_exists = mutka_file_exists(config->trusted_publkey_path);
    bool privkey_exists = mutka_file_exists(config->trusted_privkey_path);

    return (publkey_exists && privkey_exists);
}

bool mutka_cfg_generate_trustedkeys(struct mutka_client_cfg* config,
        char* privkey_passphase, size_t passphase_len) {

    // 'trusted_peers_dir' should contain 'mutka_cfgdir' as parent directory.
    if(!mutka_mkdir_p(config->trusted_peers_dir, S_IRWXU)) {
        return false;
    }

    if(!mutka_file_exists(config->trusted_privkey_path)) {
        if(creat(config->trusted_privkey_path, S_IRUSR | S_IWUSR) < 0) {
            mutka_set_errmsg("Failed to create trusted"
                    " private key file | %s", strerror(errno));
            return false;
        }
    }

    if(!mutka_file_exists(config->trusted_publkey_path)) {
        if(creat(config->trusted_publkey_path, S_IRUSR | S_IWUSR) < 0) {
            mutka_set_errmsg("Failed to create trusted"
                    " public key file | %s", strerror(errno));
            return false;
        }
    }


    struct mutka_keypair trusted_keys = mutka_init_keypair();
    if(!mutka_openssl_ED25519_keypair(&trusted_keys)) {
        return false;
    }


    // Use scrypt to derieve stronger and more suitable key for AES.
    // It will be used to encrypt the ED25519 private key.

    struct mutka_str derived_key;
    mutka_str_alloc(&derived_key);

    char scrypt_salt[16] = { 0 };

    mutka_openssl_scrypt(
            &derived_key, 
            32, // Output size
            privkey_passphase, passphase_len,
            scrypt_salt, sizeof(scrypt_salt));

    mutka_dump_strbytes(&derived_key, "derived_key");

    // TODO continue here...


    mutka_str_clear(&derived_key);
    mutka_str_free(&derived_key);
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


