#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <openssl/rand.h>
#include <dirent.h>

#define MUTKA_CLIENT
#include "../include/client.h"
#include "../include/mutka.h"
#include "../include/memory.h"
#include "../include/rng.h"

#define CLIENT_PRIVATE_IDENTITY_FILE_HEADER "libmutka-client_private-identity"


#include <stdio.h> // Temporary.



// TODO: Move this away from here...
static struct client_global {
    
    pthread_t recv_thread;

}
global;


void* mutka_client_recv_thread(void* arg);

void mutka_client_handle_packet(struct mutka_client* client);



static bool p_mutka_add_config_file
(
    struct mutka_str* cfg_root,
    struct mutka_str* cfg_root_tmp,
    char* output,
    char* nickname,
    size_t nickname_length,
    char* new_filepath
){
    mutka_str_move(cfg_root_tmp, cfg_root->bytes, cfg_root->size);

    mutka_str_append(cfg_root_tmp, nickname, nickname_length);
    mutka_str_append(cfg_root_tmp, new_filepath, strlen(new_filepath));

    if(cfg_root_tmp->size >= MUTKA_PATH_MAX) {
        mutka_set_errmsg("Error while creating config file path. \"%s\" is too long.", cfg_root_tmp->bytes);
        return false;
    }

    if(!mutka_file_exists(cfg_root_tmp->bytes)) {
        if(creat(cfg_root_tmp->bytes, S_IRUSR | S_IWUSR) < 0) {
            mutka_set_errmsg("Failed to create config file \"%s\"", cfg_root_tmp->bytes);
            return false;
        }
    }

    memcpy(output, cfg_root_tmp->bytes, cfg_root_tmp->size);
    return true;
}

static bool p_mutka_add_config_dir
(
    struct mutka_str* cfg_root,
    struct mutka_str* cfg_root_tmp,
    char* output,
    char* new_path
){
    mutka_str_move(cfg_root_tmp, cfg_root->bytes, cfg_root->size);
    mutka_str_append(cfg_root_tmp, new_path, strlen(new_path));
    if(mutka_str_lastbyte(cfg_root_tmp) != '/') {
        mutka_str_pushbyte(cfg_root_tmp, '/');
    }

    mutka_str_nullterm(cfg_root_tmp);

    if(cfg_root_tmp->size >= MUTKA_PATH_MAX) {
        mutka_set_errmsg("Error while creating config path. '%s' is too long.", cfg_root_tmp->bytes);
        return false;
    }
    
    if(!mutka_dir_exists(cfg_root_tmp->bytes)) {
        mutka_mkdir_p(cfg_root_tmp->bytes, S_IRWXU);
    }
    
    memcpy(output, cfg_root_tmp->bytes, cfg_root_tmp->size);
    return true;
}


bool mutka_validate_client_cfg
(
    struct mutka_client_cfg* config,
    char* nickname
){
    bool result = false;

    if(!config->accept_new_trusted_host_callback) {
        mutka_set_errmsg("\"accept_new_trusted_host_callback\" is missing.");
        goto out;
    }

    if(!config->accept_hostkey_change_callback) {
        mutka_set_errmsg("\"accept_hostkey_change_callback\" is missing.");
        goto out;
    }

    if(!config->confirm_server_captcha) {
        mutka_set_errmsg("\"confirm_server_captcha\" is missing.");
        goto out;
    }



    size_t nickname_len = strlen(nickname);
    if(nickname_len == 0) {
        mutka_set_errmsg("Nickname is required.");
        goto out;
    }

    if(nickname_len >= MUTKA_NICKNAME_MAX) {
        mutka_set_errmsg("Nickname is too long. max length is %i", MUTKA_NICKNAME_MAX);
        goto out;
    }

    memset(config->nickname, 0, sizeof(config->nickname));
    memcpy(config->nickname, nickname, nickname_len);


    config->flags = 0;

    // Config directory is copied to 'struct mutka_str' 
    // for making changes to it easier.
    /*
        Example how the config directory looks like:
        
        /home/user/.mutka/
        '- username123/
           |- username123.trusted_hosts
           |- username123.public_identity_key
           |- username123.private_identity_key (encrypted)
           '- trusted_peers/
              |- friend_A.public_identity_key
              '- friend_B.public_identity_key
    */

    struct mutka_str cfg_root; // Config path.
    struct mutka_str cfg_root_tmp;
    mutka_str_alloc(&cfg_root);
    mutka_str_alloc(&cfg_root_tmp);


    if(config->use_default_cfgdir) {

        struct passwd* pw = getpwuid(getuid());
        if(!pw) {
            mutka_set_errmsg("Failed to get user passwd "
                    "file entry (for home directory) | %s", strerror(errno));
            goto free_and_out;
        }

        size_t pwdir_len = strlen(pw->pw_dir);
        if(pwdir_len == 0) {
            mutka_set_errmsg("User doesnt have home directory? "
                    "(struct passwd* pw, pw->pw_dir length is zero)");
            goto free_and_out;
        }

    
        mutka_str_move(&cfg_root, pw->pw_dir, pwdir_len);
        if(mutka_str_lastbyte(&cfg_root) != '/') {
            mutka_str_pushbyte(&cfg_root, '/');
        }
        mutka_str_append(&cfg_root, ".mutka", 6);
    }
    else {
        // User has chosen a config directory.
        
        size_t user_cfgdir_len = strlen(config->mutka_cfgdir);
        if(user_cfgdir_len == 0) {
            mutka_set_errmsg("When config.use_default_cfgdir is set to 'false', "
                    "config.mutka_cfgdir cant be empty.");
            goto free_and_out;
        }

        if(user_cfgdir_len >= MUTKA_PATH_MAX) {
            mutka_set_errmsg("Custom config path is too long.");
        }

        mutka_str_move(&cfg_root, config->mutka_cfgdir, user_cfgdir_len);
    }


    // Add nickname to config path.

    if(mutka_str_lastbyte(&cfg_root) != '/') {
        mutka_str_pushbyte(&cfg_root, '/');
    }

    mutka_str_append(&cfg_root, nickname, nickname_len);
    mutka_str_pushbyte(&cfg_root, '/');

    if(!mutka_dir_exists(cfg_root.bytes)) {
        mutka_mkdir_p(cfg_root.bytes, S_IRWXU);
    }



    // Copy config path for editing.
    mutka_str_move(&cfg_root_tmp, cfg_root.bytes, cfg_root.size);


    if(!p_mutka_add_config_dir(&cfg_root, &cfg_root_tmp, config->trusted_peers_dir, "trusted_peers")) {
        goto free_and_out;
    }

    if(!p_mutka_add_config_file(&cfg_root, &cfg_root_tmp, config->private_identity_path,
                nickname, nickname_len, ".private_identity_key")) {
        goto free_and_out;
    }
    
    if(!p_mutka_add_config_file(&cfg_root, &cfg_root_tmp, config->public_identity_path,
                nickname, nickname_len, ".public_identity_key")) {
        goto free_and_out;
    }
    
    if(!p_mutka_add_config_file(&cfg_root, &cfg_root_tmp, config->trusted_hosts_path,
                nickname, nickname_len, ".trusted_hosts")) {
        goto free_and_out;
    }

    printf("mutka_cfgdir          = '%s'\n", config->mutka_cfgdir);
    printf("trusted_peers_dir     = '%s'\n", config->trusted_peers_dir);
    printf("private_identity_path = '%s'\n", config->private_identity_path);
    printf("public_identity_path  = '%s'\n", config->public_identity_path);
    printf("trusted_hosts_path    = '%s'\n", config->trusted_hosts_path);
    printf("nickname              = '%s'\n", config->nickname);
    result = true;

    config->flags |= MUTKA_CCFLG_CONFIG_VALIDATED;


free_and_out:
    mutka_str_free(&cfg_root);
    mutka_str_free(&cfg_root_tmp);

out:
    return result;
}

static bool p_mutka_read_public_identity(struct mutka_client_cfg* config) {
    bool result = false;
    char* file_data = NULL;
    size_t file_size = 0;
    if(!mutka_map_file(config->public_identity_path, PROT_READ,
                &file_data, &file_size)) {
        return false;
    }

    if(file_size != sizeof(config->identity_publkey)) {
        mutka_set_errmsg("Unexpected public identity file size.");
        goto unmap_and_out;
    }

    memcpy(config->identity_publkey.bytes, file_data, file_size);
    
    result = true;
unmap_and_out:
    munmap(file_data, file_size);
    return result;
}


bool mutka_client_identity_exists(struct mutka_client_cfg* config) {

    if(!mutka_file_exists(config->private_identity_path)) {
        return false;
    }
    if(!mutka_file_exists(config->public_identity_path)) {
        return false;
    }

    return 
        (mutka_file_size(config->private_identity_path) > 0) &&
        (mutka_file_size(config->public_identity_path) > 0);
}



bool mutka_new_client_identity
(
    struct mutka_client_cfg* config,
    char* passphase, 
    size_t passphase_len
){
    bool result = false;
    key_mldsa87_publ_t public_key;
    key_mldsa87_priv_t private_key;

    if(!mutka_openssl_MLDSA87_keypair(&private_key, &public_key)) {
        mutka_set_errmsg("Failed to generate ML-DSA-87 keypair.");
        goto out;
    }

    char* buffer = NULL;

    uint8_t scrypt_salt[SCRYPT_SALT_LEN] = { 0 };
    uint8_t gcm_iv[AESGCM_IV_LEN] = { 0 };
    uint8_t gcm_tag[AESGCM_TAG_LEN] = { 0 };

    RAND_bytes(scrypt_salt, sizeof(scrypt_salt));
    RAND_bytes(gcm_iv, sizeof(gcm_iv));

    char* gcm_aad = CLIENT_PRIVATE_IDENTITY_FILE_HEADER;
    size_t gcm_aad_len = strlen(gcm_aad);

    struct mutka_str privkey_cipher;
    struct mutka_str derived_key;
    mutka_str_alloc(&derived_key);
    mutka_str_alloc(&privkey_cipher);

    if(!mutka_openssl_scrypt(
                &derived_key, 32, /* Output length */
                passphase,
                passphase_len,
                scrypt_salt,
                sizeof(scrypt_salt))) {
        mutka_set_errmsg("%s: mutka_openssl_scrypt failed.", __func__);
        goto free_and_out;
    }


    if(!mutka_openssl_AES256GCM_encrypt(
                &privkey_cipher,
                gcm_tag,
                (uint8_t*)derived_key.bytes,
                gcm_iv,
                gcm_aad,
                gcm_aad_len,
                private_key.bytes,
                sizeof(private_key.bytes))) {
        mutka_set_errmsg("Failed to encrypt private-identity key.");
        goto free_and_out;
    }

    /*
        Private identity key file structure:

        [gcm_aad]
        [gcm_iv]
        [gcm_tag]
        [scrypt_salt]
        [encrypted mldsa87 private key]

    */

    buffer = malloc(
        gcm_aad_len +
        sizeof(gcm_iv) +
        sizeof(gcm_tag) + 
        sizeof(scrypt_salt) +
        privkey_cipher.size);

    size_t buffer_offset = 0;
    
    // GCM AAD.
    memmove(buffer,
            gcm_aad,
            gcm_aad_len);
    buffer_offset += gcm_aad_len;

    // GCM IV.
    memmove(buffer + buffer_offset,
            gcm_iv,
            sizeof(gcm_iv));
    buffer_offset += sizeof(gcm_iv);

    // GCM TAG.
    memmove(buffer + buffer_offset,
            gcm_tag,
            sizeof(gcm_tag));
    buffer_offset += sizeof(gcm_tag);

    // SCRYPT SALT.
    memmove(buffer + buffer_offset,
            scrypt_salt,
            sizeof(scrypt_salt));
    buffer_offset += sizeof(scrypt_salt);

    // CIPHER.
    memmove(buffer + buffer_offset,
            privkey_cipher.bytes,
            privkey_cipher.size);
    buffer_offset += privkey_cipher.size;


    if(!mutka_write_file(config->private_identity_path, buffer, buffer_offset)) {
        mutka_set_errmsg("Failed to save new private identity.");
        goto free_and_out;
    }

    if(!mutka_write_file(config->public_identity_path, public_key.bytes, sizeof(public_key.bytes))) {
        mutka_set_errmsg("Failed to save new public identity.");
        goto free_and_out;
    }

    result = true;

free_and_out:
    if(buffer) {
        free(buffer);
    }
    mutka_str_free(&derived_key);
    mutka_str_free(&privkey_cipher);

out:
    return result;
}


bool mutka_decrypt_client_identity
(
    struct mutka_client_cfg* config,
    char* passphase, 
    size_t passphase_len
){
    bool result = false;

    char* file_data = NULL;
    size_t file_size = 0;
    
    struct mutka_str privkey_cipher;
    struct mutka_str derived_key;
    struct mutka_str decrypted_privkey;

    mutka_str_alloc(&privkey_cipher);
    mutka_str_alloc(&derived_key);
    mutka_str_alloc(&decrypted_privkey);

    char gcm_aad[strlen(CLIENT_PRIVATE_IDENTITY_FILE_HEADER)];
    uint8_t gcm_iv[AESGCM_IV_LEN] = { 0 };
    uint8_t gcm_tag[AESGCM_TAG_LEN] = { 0 };
    uint8_t scrypt_salt[SCRYPT_SALT_LEN] = { 0 };


    if(!mutka_map_file(config->private_identity_path, PROT_READ, &file_data, &file_size)) {
        goto out;
    }

    /*
        Private identity key file structure:

        [gcm_aad]
        [gcm_iv]
        [gcm_tag]
        [scrypt_salt]
        [encrypted mldsa87 private key]

    */

    size_t byte_offset = 0;

    // GCM AAD.
    if(byte_offset + sizeof(gcm_aad) > file_size) {
        mutka_set_errmsg("Expected gcm aad but got EOF.");
        goto unmap_and_out;
    }
    memmove(gcm_aad,
            file_data + byte_offset,
            sizeof(gcm_aad));
    byte_offset += sizeof(gcm_aad);


    // GCM IV.
    if(byte_offset + sizeof(gcm_iv) > file_size) {
        mutka_set_errmsg("Expected gcm iv but got EOF.");
        goto unmap_and_out;
    }
    memmove(gcm_iv,
            file_data + byte_offset,
            sizeof(gcm_iv));
    byte_offset += sizeof(gcm_iv);


    // GCM TAG.
    if(byte_offset + sizeof(gcm_tag) > file_size) {
        mutka_set_errmsg("Expected gcm tag but got EOF.");
        goto unmap_and_out;
    }
    memmove(gcm_tag,
            file_data + byte_offset,
            sizeof(gcm_tag));
    byte_offset += sizeof(gcm_tag);


    // SCRYPT SALT.
    if(byte_offset + sizeof(scrypt_salt) > file_size) {
        mutka_set_errmsg("Expected scrypt salt but got EOF.");
        goto unmap_and_out;
    }
    memmove(scrypt_salt,
            file_data + byte_offset,
            sizeof(scrypt_salt));
    byte_offset += sizeof(scrypt_salt);


    // Remaining is private key cipher.
    int64_t remaining = file_size - byte_offset;
    if(remaining <= 0) {
        mutka_set_errmsg("Expected private identity key cipher but got EOF.");
        goto unmap_and_out;
    }

    mutka_str_reserve(&privkey_cipher, remaining);
    mutka_str_move(&privkey_cipher, file_data + byte_offset, remaining);


    if(!mutka_openssl_scrypt(&derived_key, 32, /* Output size*/
                passphase,
                passphase_len,
                scrypt_salt,
                sizeof(scrypt_salt))) {
        mutka_set_errmsg("Failed to derive key for decrypting private identity key.");
        goto unmap_and_out;
    }

    if(!mutka_openssl_AES256GCM_decrypt(
                &decrypted_privkey,
                (uint8_t*)derived_key.bytes,
                gcm_iv,
                gcm_aad,
                sizeof(gcm_aad),
                (char*)gcm_tag,
                sizeof(gcm_tag),
                privkey_cipher.bytes,
                privkey_cipher.size)) {
        mutka_set_errmsg("Failed to decrypt private identity key.");
        goto unmap_and_out;
    }


    if(decrypted_privkey.size != sizeof(config->identity_privkey.bytes)) {
        mutka_set_errmsg("Unexpected private identity key length.");
        goto unmap_and_out;
    }

    memmove(config->identity_privkey.bytes,
            decrypted_privkey.bytes,
            decrypted_privkey.size);

    result = true;
    config->flags |= MUTKA_CCFLG_HAS_PRIVIDENTITY_KEY;

unmap_and_out:
    munmap(file_data, file_size);
    mutka_str_free(&privkey_cipher);
    mutka_str_free(&derived_key);
    mutka_str_free(&decrypted_privkey);

out:
    return result;
}

static bool p_mutka_read_trusted_peers(struct mutka_client* client) {

    DIR* dir = NULL;
    struct dirent* ent = NULL;


    dir = opendir(client->config.trusted_peers_dir);
    if(!dir) {
        mutka_set_errmsg("Failed to open directory \"%s\"",
                client->config.trusted_peers_dir);
        return false;
    }

    size_t num_trusted_peers_alloc = 1;
    
    client->num_trusted_peers = 0;
    client->trusted_peers_sha512 
        = calloc(num_trusted_peers_alloc,
                sizeof *client->trusted_peers_sha512);

    while((ent = readdir(dir))) {
        if(ent->d_type != DT_REG) {
            continue;
        }

        // Resize the array if needed.
        if(client->num_trusted_peers+1 >= num_trusted_peers_alloc) {
            size_t old_num_alloc = num_trusted_peers_alloc;
            client->trusted_peers_sha512
                = mutka_srealloc_array(
                        sizeof *client->trusted_peers_sha512,
                        client->trusted_peers_sha512,
                        &num_trusted_peers_alloc,
                        num_trusted_peers_alloc + 16);
            if(old_num_alloc == num_trusted_peers_alloc) {
                mutka_set_errmsg("%s: Failed to allocate more memory for"
                        " \"client->trusted_peers_sha512\"", __func__);
                closedir(dir);
                return false;
            }
        }


        char peer_publkey_path [MUTKA_PATH_MAX*2] = { 0 };
        snprintf(peer_publkey_path,
                sizeof(peer_publkey_path)-1,
                "%s%s",
                client->config.trusted_peers_dir,
                ent->d_name);

        if(!mutka_file_exists(peer_publkey_path)) {
            mutka_set_errmsg("WARNING! \"%s\" Dont exist.",
                    peer_publkey_path);
            continue;
        }

        char* file_data = NULL;
        size_t file_size = 0;

        if(!mutka_map_file(peer_publkey_path, PROT_READ,
                    &file_data,
                    &file_size)) {
            mutka_set_errmsg("WARNING! Failed to map file \"%s\"",
                    peer_publkey_path);
            continue;
        }

        SHA512((uint8_t*)file_data,
                file_size,
                client->trusted_peers_sha512[client->num_trusted_peers++].bytes);

        munmap(file_data, file_size);
    }

    if(client->num_trusted_peers == 0) {
        mutka_set_errmsg("WARNING: You dont have any trusted peer's public keys saved.");
    }

    closedir(dir);

    return true;
}



struct mutka_client* mutka_connect
(
    struct mutka_client_cfg* config,
    char* host,
    char* port
){
    struct mutka_client* client = NULL;
    
    if(!p_mutka_read_public_identity(config)) {
        mutka_set_errmsg("Failed to read public identity key.");
        goto out;
    }

    if(!(config->flags & MUTKA_CCFLG_HAS_PRIVIDENTITY_KEY)) {
        mutka_set_errmsg("Client configuration doesnt contain identity keys.");
        goto out;
    }

    if(!(config->flags & MUTKA_CCFLG_CONFIG_VALIDATED)) {
        mutka_set_errmsg("Client configuration doesnt seem to be validated.");
        goto out;
    }


    const int port_num = atoi(port);
    if((port_num < 0) || (port_num > UINT16_MAX)) {
        mutka_set_errmsg("Given host port \"%s\" cannot be correct. It must be in range of 0 to %i",
                port, UINT16_MAX);
        goto out;
    }

    client = malloc(sizeof *client);
    client->env = MUTKA_ENV_NULL;
    client->config = *config;
    client->flags = 0;
    client->peer_msg_keys = NULL;
    client->num_peer_msg_keys = 0;
    mutka_str_alloc(&client->plaintext_msg);
    pthread_mutex_init(&client->mutex, NULL);


    if(!p_mutka_read_trusted_peers(client)) {
        free(client);
        client = NULL;
        goto out;
    }

    // Copy host address for future use.
    client->host_addr_len = strlen(host);
    if(client->host_addr_len >= MUTKA_HOST_ADDR_MAX) {
        mutka_set_errmsg("Host address is too long");
        free(client);
        client = NULL;
        goto out;
    }
    memset(client->host_addr, 0, sizeof(client->host_addr));
    memcpy(client->host_addr, host, client->host_addr_len);

    // Copy host port for future use.
    client->host_port_len = strlen(port);
    if(client->host_port_len >= MUTKA_HOST_PORT_MAX) {
        mutka_set_errmsg("Host port is too long");
        free(client);
        client = NULL;
        goto out;
    }
    memset(client->host_port, 0, sizeof(client->host_port));
    memcpy(client->host_port, port, client->host_port_len);



    client->socket_fd = -1;
    client->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(client->socket_fd < 0) {
        mutka_set_errmsg("Failed to open socket. %s", strerror(errno));
        free(client);
        client = NULL;
        goto out;
    }

    client->socket_addr.sin_family = AF_INET;
    client->socket_addr.sin_port = htons(port_num);

    inet_pton(AF_INET, host, &client->socket_addr.sin_addr);


    int connect_result = connect(
            client->socket_fd,
            (struct sockaddr*)&client->socket_addr,
            sizeof(client->socket_addr));

    if(connect_result != 0) {
        mutka_set_errmsg("Connection failed to (%s:%i) | %s", 
                host, port_num, strerror(errno));
        close(client->socket_fd);
        free(client);
        client = NULL;
        goto out;
    }

    client->env = MUTKA_ENV_CLIENT;

    // Initialize client structure.
    mutka_inpacket_init(&client->inpacket);
    mutka_alloc_rpacket(&client->out_raw_packet, MUTKA_RAW_PACKET_DEFMEMSIZE);
    mutka_alloc_rpacket(&client->inpacket.raw_packet, MUTKA_RAW_PACKET_DEFMEMSIZE);


    // Create thread for receiving data.
    pthread_create(&global.recv_thread,
            NULL, mutka_client_recv_thread, client);

out:
    return client;
}


void mutka_init_metadata_key_exchange(struct mutka_client* client) {

    if(!mutka_generate_cipher_keys(&client->mtdata_keys)) {
        mutka_set_errmsg("Failed to generate cipher keys.");
        client->flags |= MUTKA_CLFLG_SHOULD_DISCONNECT;
        return;
    }

    mutka_rpacket_prep(&client->out_raw_packet, MPACKET_EXCHANGE_METADATA_KEYS);
    mutka_rpacket_add_ent(&client->out_raw_packet,
            "x25519_public",
            client->mtdata_keys.x25519_publkey.bytes,
            sizeof(client->mtdata_keys.x25519_publkey.bytes),
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&client->out_raw_packet,
            "mlkem_public",
            client->mtdata_keys.mlkem_publkey.bytes,
            sizeof(client->mtdata_keys.mlkem_publkey.bytes),
            RPACKET_ENCODE);

    mutka_send_clear_rpacket(client->socket_fd, &client->out_raw_packet);
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

    if(client->env == MUTKA_ENV_CLIENT) {
        mutka_str_free(&client->plaintext_msg);
        mutka_free_rpacket(&client->out_raw_packet);
        mutka_free_packet(&client->inpacket);
        if(client->peer_msg_keys) {
            free(client->peer_msg_keys);
            client->peer_msg_keys = NULL;
        }
        free(client);
    }
}

#include <stdio.h> // <- temp


void* mutka_client_recv_thread(void* arg) {
    printf("%s: started\n",__func__);

    struct mutka_client* client = (struct mutka_client*)arg;
    bool running = true;
    while(running) {
        pthread_mutex_lock(&client->mutex);

        int rd = mutka_recv_incoming_packet(&client->inpacket, client->socket_fd);
  
        switch(rd) {
            case M_NEW_PACKET_AVAIL:
                mutka_client_handle_packet(client);
                printf("M_NEW_PACKET_AVAIL\n");
                break;

            case M_LOST_CONNECTION:
                client->flags |= MUTKA_CLFLG_SHOULD_DISCONNECT;
                printf("M_LOST_CONNECTION\n");
                break;

            case M_PACKET_PARSE_ERR:
                printf("M_PACKET_PARSE_ERR\n");
                break;

            case M_ENCRYPTED_RPACKET:
                printf("M_ENCRYPTED_RPACKET\n");
                if(mutka_parse_encrypted_rpacket(
                        &client->inpacket,
                        &client->inpacket.raw_packet,
                        &client->mtdata_keys.hshared_key)) {
                    mutka_client_handle_packet(client);
                }
                break;
        }

        if((client->flags & MUTKA_CLFLG_SHOULD_DISCONNECT)) {
            running = false;
        }

        pthread_mutex_unlock(&client->mutex);
        mutka_sleep_ms(1); // Small delay to limit CPU usage.
    }

    return NULL;
}

static bool p_mutka_client_save_trusted_host
(
    struct mutka_client* client,
    char* host_tag,
    size_t host_tag_len,
    key_mldsa87_publ_t* host_publkey
){
    if(!client->config.accept_new_trusted_host_callback(client, NULL)) {
        return false;
    }

    char buffer[host_tag_len + sizeof(host_publkey->bytes) + 1];
    memmove(buffer, 
            host_tag, 
            host_tag_len);

    memmove(buffer + host_tag_len, 
            host_publkey->bytes,
            sizeof(host_publkey->bytes));

    buffer[sizeof(buffer)-1] = '\n';
    return mutka_file_append(client->config.trusted_hosts_path, buffer, sizeof(buffer));
}


static bool p_mutka_client_process_host_signature(struct mutka_client* client) {
    bool result = false;
 
    // "host_addr@host_port:"
    char host_tag[128] = { 0 };
    const ssize_t host_tag_len = snprintf(host_tag, sizeof(host_tag)-1, 
            "%s@%s:", client->host_addr, client->host_port);

    if(host_tag_len <= 0) {
        mutka_set_errmsg("%s: %s", __func__, strerror(errno));
        goto out;
    }
   
    struct mutka_str* encoded_host_publkey = &client->inpacket.elements[0].data;
    key_mldsa87_publ_t host_publkey;

    const uint32_t decoded_host_publkey_len 
        = mutka_get_decoded_buffer_len(encoded_host_publkey->size);


    if(decoded_host_publkey_len != sizeof(host_publkey.bytes)) {
        mutka_set_errmsg("%s: Received host public key length doesnt match expected value.", 
                __func__);
        goto out;
    }


    if(!mutka_decode(host_publkey.bytes, sizeof(host_publkey.bytes),
                encoded_host_publkey->bytes,
                encoded_host_publkey->size)) {
        mutka_set_errmsg("%s: Failed to decode host public key.", __func__);
        goto out;
    }

    // Maybe the "trusted_hosts" file is never used before.
    if(mutka_file_size(client->config.trusted_hosts_path) == 0) {
        if(p_mutka_client_save_trusted_host(
                client,
                host_tag, host_tag_len,
                &host_publkey)) {
            goto new_host_saved;
        }
        goto out;
    }


    char* hosts_file = NULL;
    size_t hosts_file_size = 0;

    if(!mutka_map_file(client->config.trusted_hosts_path, PROT_READ | PROT_WRITE, 
                &hosts_file, &hosts_file_size)) {
        goto out;
    }

    // Try to find host tag.
    // If found, the saved combined hash will follow.
    const ssize_t host_index = mutka_charptr_find(hosts_file, hosts_file_size, host_tag, host_tag_len);
    if(host_index < 0) {
        // Host tag was not found.
        if(p_mutka_client_save_trusted_host(
                client,
                host_tag, host_tag_len,
                &host_publkey)) {
            goto new_host_saved;
        }
        
        goto unmap_and_out;       
    }
    
    const char* search_begin = hosts_file + host_index + host_tag_len;
    const char* search_end = search_begin + sizeof(host_publkey.bytes);

    if(search_end > hosts_file + hosts_file_size) {
        mutka_set_errmsg("Could not find correct host tag index from \"trusted_hosts\" file.\n"
                "(search region is out of bounds) Maybe the file was modified incorrectly?");
        goto unmap_and_out;
    }

    if(search_end - search_begin != sizeof(host_publkey.bytes)) {
        mutka_set_errmsg("Failed to calculate correct size search region for host signature and public key hash.");
        goto unmap_and_out;
    }

    char* byte = (char*)search_begin;
    size_t host_publkey_index = 0;
    bool   host_publkey_match = true;

    while(byte < search_end) {
        if((uint8_t)*byte != host_publkey.bytes[host_publkey_index++]) {
            host_publkey_match = false;
            break;
        }
        byte++;
    }

    if(!host_publkey_match) {
        const bool can_overwrite = client->config.accept_hostkey_change_callback(client, NULL);
        if(!can_overwrite) {
            goto unmap_and_out;
        }

        // Overwrite host signature + public key hash.
        memmove(hosts_file + host_index + host_tag_len,
                host_publkey.bytes,
                sizeof(host_publkey.bytes));

        // Synchronize memory with file to avoid undefined reads in the future.
        msync(hosts_file, hosts_file_size, MS_SYNC);
    }
    

new_host_saved:

    memmove(client->host_mldsa87_publkey.bytes,
            host_publkey.bytes,
            sizeof(host_publkey.bytes));


    result = true;

unmap_and_out:
    munmap(hosts_file, hosts_file_size);

out:
    if(!result) {
        client->flags |= MUTKA_CLFLG_SHOULD_DISCONNECT;
    }
    return result;
}

void mutka_send_captcha_answer(struct mutka_client* client, char* answer, size_t answer_len) {
    if(!(client->flags & MUTKA_CLFLG_WAITING_CAPTCHA_INPUT)) {
        mutka_set_errmsg("%s: Server has not requested a captcha answer.", __func__);
        return;
    }

    mutka_rpacket_prep(&client->out_raw_packet, MPACKET_CAPTCHA);
    mutka_rpacket_add_ent(&client->out_raw_packet,
            "answer",
            answer,
            answer_len,
            RPACKET_ENCODE_NONE);

    mutka_send_clear_rpacket(client->socket_fd, &client->out_raw_packet);
    client->flags &= ~MUTKA_CLFLG_WAITING_CAPTCHA_INPUT;
}

// This function is called from 'mutka_client_handle_packet' MPACKET_GENERAL_SERVER_INFO:
static void p_mutka_client_fully_connected(struct mutka_client* client) {
   
    if(client->peer_msg_keys) {
        free(client->peer_msg_keys);
        client->peer_msg_keys = NULL;
    }

    client->num_peer_msg_keys = 0;
    client->peer_msg_keys = calloc(
            client->host_max_clients,
            sizeof(*client->peer_msg_keys));

    mutka_deposit_new_msgkeys(client);
}


static bool p_can_trust_peer(struct mutka_client* client, key_mldsa87_publ_t* peer_identity_publkey) {


    return false;
}

// Encrypts the message with fresh cipher keys for next trusted peer.
// And this function is called again when MPACKET_SERVER_MSG_ACK is receiver from server.
static bool p_encrypt_message_for_next_peer(struct mutka_client* client) {
    bool result = false;

    if(client->num_peer_msg_keys <= 0) {
        client->flags &= ~MUTKA_CLFLG_SENDING_MSG;
        goto out;
    }

    printf("(TODO) %s: Check if receiver is considered trusted.\n",__func__);

    struct mutka_client_peer_msgkeys* 
        peer_msgkeys = &client->peer_msg_keys[client->num_peer_msg_keys - 1];

    struct mutka_cipher_keys self_keys;
    if(!mutka_generate_cipher_keys(&self_keys)) {
        mutka_set_errmsg("%s: Failed to generate cipher keys.", __func__);
        goto out;
    }


    uint8_t hkdf_salt [HKDF_SALT_LEN] = { 0 };
    uint8_t gcm_iv [AESGCM_IV_LEN] = { 0 };
    uint8_t gcm_tag [AESGCM_TAG_LEN] = { 0 };

    char* gcm_aad = "TESTING";
    size_t gcm_aad_len = strlen(gcm_aad);

    struct mutka_str msg_cipher;
    mutka_str_alloc(&msg_cipher);

    RAND_bytes(hkdf_salt, sizeof(hkdf_salt));
    RAND_bytes(gcm_iv, sizeof(gcm_iv));


    // Add randomized number of null bytes to plaintext before encrypting
    // to make it useless to estimate the message length.
    struct mutka_str plaintext;
    mutka_str_alloc(&plaintext);
    mutka_str_move(&plaintext, 
            client->plaintext_msg.bytes,
            client->plaintext_msg.size);

    int random_length = mutka_rng(
            (struct mutka_rngcfg){
                .iterations = 8,
                .max_value = 1024*2
            });
    mutka_str_reserve(&plaintext, plaintext.memsize + random_length);

    for(int i = 0; i < random_length; i++) {
        mutka_str_pushbyte(&plaintext, '\0');
    }


    key128bit_t hybrid_key;
    key_mlkem1024_cipher_t mlkem_ciphertext;

    if(!mutka_hybrid_kem_encaps(
                &hybrid_key,
                &mlkem_ciphertext,
                &self_keys,
                &peer_msgkeys->x25519_publkey,
                &peer_msgkeys->mlkem_publkey,
                hkdf_salt,
                MUTKA_VERSION_STR"(ENCRYPTED_MESSAGE_FOR_PEER)")) {
        mutka_set_errmsg("%s: mutka_hybrid_kem_encaps() Failed!", __func__);
        goto free_and_out;
    }

    if(!mutka_openssl_AES256GCM_encrypt(
                &msg_cipher,
                gcm_tag,
                hybrid_key.bytes,
                gcm_iv,
                gcm_aad,
                gcm_aad_len,
                plaintext.bytes,
                plaintext.size)) {
        mutka_set_errmsg("%s: Failed to encrypt message.", __func__);
        goto free_and_out;
    }



    // Create signature from SHA512(outgoing_keys) + SHA512(message_cipher);

    uint8_t sign_data[SHA512_DIGEST_LENGTH * 3] = { 0 };

    // Self X25519 public key.
    SHA512(self_keys.x25519_publkey.bytes,
            sizeof(self_keys.x25519_publkey.bytes),
            sign_data);

    // ML-KEM-1024 Ciphertext.
    SHA512(mlkem_ciphertext.bytes,
            sizeof(mlkem_ciphertext.bytes),
            sign_data + SHA512_DIGEST_LENGTH);

    // Message ciphertext.
    SHA512((uint8_t*)msg_cipher.bytes,
            msg_cipher.size,
            sign_data + SHA512_DIGEST_LENGTH*2);

    signature_mldsa87_t signature;
    if(!mutka_openssl_MLDSA87_sign(
                MUTKA_VERSION_STR"(SIGN_ENCRYPTED_MESSAGE_FOR_PEER)",
                &signature,
                &client->config.identity_privkey,
                sign_data,
                sizeof(sign_data))) {
        mutka_set_errmsg("%s: Failed to create signature.", __func__);
        goto free_and_out;
    }

   
    // Start preparing packet to send.
    
    mutka_rpacket_prep(&client->out_raw_packet, MPACKET_SEND_MSG);
  
    printf("Receiver: %i\n", peer_msgkeys->uid);

    mutka_rpacket_add_ent(&client->out_raw_packet,
            "receiver_uid",
            (uint8_t*)&peer_msgkeys->uid,
            sizeof(peer_msgkeys->uid),
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&client->out_raw_packet,
            "msg_ciphertext",
            msg_cipher.bytes,
            msg_cipher.size,
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&client->out_raw_packet,
            "gcm_iv",
            gcm_iv,
            sizeof(gcm_iv),
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&client->out_raw_packet,
            "gcm_tag",
            gcm_tag,
            sizeof(gcm_tag),
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&client->out_raw_packet,
            "gcm_aad",
            gcm_aad,
            gcm_aad_len,
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&client->out_raw_packet,
            "x25519_public",
            self_keys.x25519_publkey.bytes,
            sizeof(self_keys.x25519_publkey.bytes),
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&client->out_raw_packet,
            "mlkem_ciphertext",
            mlkem_ciphertext.bytes,
            sizeof(mlkem_ciphertext.bytes),
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&client->out_raw_packet,
            "hkdf_salt",
            hkdf_salt,
            sizeof(hkdf_salt),
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&client->out_raw_packet,
            "signature",
            signature.bytes,
            sizeof(signature.bytes),
            RPACKET_ENCODE);

    mutka_send_encrypted_rpacket(
            client->socket_fd,
            &client->out_raw_packet,
            &client->mtdata_keys.hshared_key);


    printf("Outgoing Packet Size = %i\n", client->out_raw_packet.size);


    printf("%s: %s\n", __func__, client->plaintext_msg.bytes);
    client->num_peer_msg_keys--;

    result = true;

free_and_out:
    mutka_str_free(&msg_cipher);
    mutka_str_free(&plaintext);
out:
    return result;
}

// This function is called when 
// "is_last_peer" is set to 'true' in MPACKET_GET_PEER_PUBLKEYS
static void p_handle_received_msg_keys(struct mutka_client* client) {
    
    // For now client can only send message with the received peer msg public keys.
    // Not sure if there is going to be some features
    // which may also require them in the future.

    printf("%s\n",__func__);

    if(p_encrypt_message_for_next_peer(client)) {
        client->flags |= MUTKA_CLFLG_SENDING_MSG;
    }
}


void mutka_client_handle_packet(struct mutka_client* client) {
    // NOTE: client->mutex is locked here.

    printf("%s: (packet id = %i)\n", __func__, client->inpacket.id);

    // NOTE: Remember to return from switch statement instead of break
    //       if handling internal packets.

    // TODO: Create better system to handle packet element sizes

    // Check for internal packets first.
    switch(client->inpacket.id) {

        case MPACKET_MSG_RECV:
            printf("MPACKET_MSG_RECV: %li elements\n", client->inpacket.num_elements);
            return;

        case MPACKET_SERVER_MSG_ACK:
            p_encrypt_message_for_next_peer(client);
            break;

        case MPACKET_GET_PEER_PUBLKEYS:
            if(client->inpacket.num_elements != 5) {
                mutka_set_errmsg("Failed to receive peer public msg keys.");
                return;
            }
            {
                struct mutka_packet_elem* peer_uid_elem = &client->inpacket.elements[0];
                struct mutka_packet_elem* identity_publkey_elem = &client->inpacket.elements[1];
                struct mutka_packet_elem* signature_elem = &client->inpacket.elements[2];
                struct mutka_packet_elem* x25519_publkey_elem = &client->inpacket.elements[3];
                struct mutka_packet_elem* mlkem_publkey_elem = &client->inpacket.elements[4];

                printf("MPACKET_GET_PEER_PUBLKEYS\n");

                if(client->num_peer_msg_keys >= client->host_max_clients) {
                    mutka_set_errmsg("MPACKET_GET_PEER_PUBLKEYS: "
                            "Receiving more peer message keys than there are maximum clients on server.");
                    return;
                }

                struct mutka_client_peer_msgkeys* peer_keys
                    = &client->peer_msg_keys[client->num_peer_msg_keys++];

                if(!mutka_decode(peer_keys->identity_publkey.bytes,
                            sizeof(peer_keys->identity_publkey.bytes),
                            identity_publkey_elem->data.bytes,
                            identity_publkey_elem->data.size)) {
                    mutka_set_errmsg("MPACKET_GET_PEER_PUBLKEYS: "
                            "Failed to decode peer identity public key.");
                    return;
                }
                if(!mutka_decode((uint8_t*)&peer_keys->uid,
                            sizeof(peer_keys->uid),
                            peer_uid_elem->data.bytes,
                            peer_uid_elem->data.size)) {
                    mutka_set_errmsg("MPACKET_GET_PEER_PUBLKEYS: "
                            "Failed to decode peer uid");
                    return;
                }
                if(!mutka_decode(peer_keys->signature.bytes,
                            sizeof(peer_keys->signature.bytes),
                            signature_elem->data.bytes,
                            signature_elem->data.size)) {
                    mutka_set_errmsg("MPACKET_GET_PEER_PUBLKEYS: "
                            "Failed to decode peer message keys signature.");
                    return;
                }
                if(!mutka_decode(peer_keys->x25519_publkey.bytes,
                            sizeof(peer_keys->x25519_publkey.bytes),
                            x25519_publkey_elem->data.bytes,
                            x25519_publkey_elem->data.size)) {
                    mutka_set_errmsg("MPACKET_GET_PEER_PUBLKEYS: "
                            "Failed to decode peer message X25519 public key.");
                    return;
                }
                if(!mutka_decode(peer_keys->mlkem_publkey.bytes,
                            sizeof(peer_keys->mlkem_publkey.bytes),
                            mlkem_publkey_elem->data.bytes,
                            mlkem_publkey_elem->data.size)) {
                    mutka_set_errmsg("MPACKET_GET_PEER_PUBLKEYS: "
                            "Failed to decode peer message ML-KEM-1024 public key.");
                    return;
                }


                // Keep asking for next peer public keys
                // until 'MPACKET_ALL_PEER_PUBLKEYS_SENT' is received.
                mutka_rpacket_prep(&client->out_raw_packet, MPACKET_GET_PEER_PUBLKEYS);
                mutka_send_encrypted_rpacket(
                        client->socket_fd,
                        &client->out_raw_packet,
                        &client->mtdata_keys.hshared_key);
            }
            return;
    
        case MPACKET_ALL_PEER_PUBLKEYS_SENT:        
            p_handle_received_msg_keys(client);
            return;

        case MPACKET_CAPTCHA:
            struct mutka_str* captcha_ascii = &client->inpacket.elements[0].data;
            mutka_str_nullterm(captcha_ascii);

            client->flags |= MUTKA_CLFLG_WAITING_CAPTCHA_INPUT;
            client->config.confirm_server_captcha(client, captcha_ascii->bytes);
            return;

        case MPACKET_HOST_PUBLIC_KEY: 
            if(client->inpacket.num_elements != 1) {
                mutka_set_errmsg("Failed to receive host public key.");
                return;
            }
            
            if(!p_mutka_client_process_host_signature(client)) {
                return;
            }

            mutka_init_metadata_key_exchange(client);
            return;
        
        case MPACKET_EXCHANGE_METADATA_KEYS:
            if(client->inpacket.num_elements != 4) {
                mutka_set_errmsg("Failed to receive complete metadata key exchange packet.");
                return;
            }
            {
                struct mutka_packet_elem* peer_x25519_elem       = &client->inpacket.elements[0];
                struct mutka_packet_elem* mlkem_cipher_elem      = &client->inpacket.elements[1];
                struct mutka_packet_elem* signature_elem         = &client->inpacket.elements[2];
                struct mutka_packet_elem* hkdf_salt_elem         = &client->inpacket.elements[3];

                uint8_t  hkdf_salt [HKDF_SALT_LEN] = { 0 };

                signature_mldsa87_t    signature;
                key128bit_t            peer_x25519_publkey;
                key_mlkem1024_cipher_t mlkem_cipher;

                if(!mutka_decode(peer_x25519_publkey.bytes, sizeof(peer_x25519_publkey.bytes),
                            peer_x25519_elem->data.bytes,
                            peer_x25519_elem->data.size)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: "
                            "Failed to decode peer X25519 public key.");
                    client->flags |= MUTKA_CLFLG_SHOULD_DISCONNECT;
                    return;
                }

                if(!mutka_decode(mlkem_cipher.bytes, sizeof(mlkem_cipher.bytes),
                            mlkem_cipher_elem->data.bytes,
                            mlkem_cipher_elem->data.size)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: "
                            "Failed to decode ML-KEM-1024 key ciphertext.");
                    client->flags |= MUTKA_CLFLG_SHOULD_DISCONNECT;
                    return;
                }

                if(!mutka_decode(signature.bytes, sizeof(signature.bytes),
                            signature_elem->data.bytes,
                            signature_elem->data.size)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: "
                            "Failed to decode signature.");
                    client->flags |= MUTKA_CLFLG_SHOULD_DISCONNECT;
                    return;
                }
                if(!mutka_decode(hkdf_salt, sizeof(hkdf_salt),
                            hkdf_salt_elem->data.bytes,
                            hkdf_salt_elem->data.size)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: "
                            "Failed to decode HKDF salt.");
                    client->flags |= MUTKA_CLFLG_SHOULD_DISCONNECT;
                    return;
                }

                const char* hkdf_info = MUTKA_VERSION_STR"(METADATAKEYS_HYBRIDKEY_HKDF)";
                const char* sign_context = MUTKA_VERSION_STR"(METADATAKEYS_SIGN_FROM_SERVER)";


                if(!mutka_hybrid_kem_decaps(
                            &client->mtdata_keys.hshared_key,
                            &client->mtdata_keys,
                            &client->host_mldsa87_publkey,
                            &peer_x25519_publkey,
                            &mlkem_cipher,
                            &signature,
                            sign_context,
                            hkdf_salt,
                            hkdf_info)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: "
                            "mutka_hybrid_kem_decaps() failed!");
                    client->flags |= MUTKA_CLFLG_SHOULD_DISCONNECT;
                    return;
                }

                printf("\033[32mMetadata key exchange with host is complete.\033[0m\n");

                // Inform the server everything is ok and we can continue.
                mutka_rpacket_prep(&client->out_raw_packet, MPACKET_METADATA_KEY_EXHCANGE_COMPLETE);
                mutka_send_clear_rpacket(client->socket_fd, &client->out_raw_packet);
            }
            return;

        case MPACKET_GENERAL_SERVER_INFO:
            // Server responded to MPACKET_METADATA_KEY_EXHCANGE_COMPLETE.

            if(client->inpacket.num_elements != 1) {
                mutka_set_errmsg("Failed to receive general server info.");
                return;
            }
            {
                struct mutka_packet_elem* max_clients_elem = &client->inpacket.elements[0];

                client->host_max_clients = 0;

                if(!mutka_decode(&client->host_max_clients,
                            sizeof(client->host_max_clients),
                            max_clients_elem->data.bytes,
                            max_clients_elem->data.size)) {
                    mutka_set_errmsg("Failed to decode \"host_max_clients\"");
                    client->flags |= MUTKA_CLFLG_SHOULD_DISCONNECT;
                    return;
                }


                p_mutka_client_fully_connected(client);
            }
            return;
    }

    client->packet_received_callback(client);
}

void mutka_deposit_new_msgkeys(struct mutka_client* client) {
    if(!mutka_generate_cipher_keys(&client->msg_keys)) {
        client->flags |= MUTKA_CLFLG_SHOULD_DISCONNECT;
        return;
    }

    // Server has to know about the public message keys.
    mutka_rpacket_prep(&client->out_raw_packet, MPACKET_DEPOSIT_PUBLIC_MSGKEYS);


    // Create signature from X25519 public key and ML-KEM-1024 public key.
    // and sign it with self private identity key.
    // This way the receiver can be sure that the keys
    // they will be using for encrypting the message
    // do belong to a trusted person and not malicious server.
    uint8_t combined_publkey_hash[SHA512_DIGEST_LENGTH * 2] = { 0 };

    SHA512(client->msg_keys.x25519_publkey.bytes,
            sizeof(client->msg_keys.x25519_publkey.bytes),
            combined_publkey_hash);

    SHA512(client->msg_keys.mlkem_publkey.bytes,
            sizeof(client->msg_keys.mlkem_publkey.bytes),
            combined_publkey_hash + SHA512_DIGEST_LENGTH);

    signature_mldsa87_t signature;
    if(!mutka_openssl_MLDSA87_sign(
                MUTKA_VERSION_STR"(PUBLIC_IDENTITY_SIGNATURE)",
                &signature,
                &client->config.identity_privkey,
                combined_publkey_hash,
                sizeof(combined_publkey_hash))) {
        mutka_set_errmsg("%s: Failed to sign public keys.", __func__);
        client->flags |= MUTKA_CLFLG_SHOULD_DISCONNECT;
    }

    mutka_rpacket_add_ent(&client->out_raw_packet,
            "signature",
            signature.bytes,
            sizeof(signature.bytes),
            RPACKET_ENCODE);
    
    mutka_rpacket_add_ent(&client->out_raw_packet,
            "public_identity",
            client->config.identity_publkey.bytes,
            sizeof(client->config.identity_publkey.bytes),
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&client->out_raw_packet,
            "public_x25519",
            client->msg_keys.x25519_publkey.bytes,
            sizeof(client->msg_keys.x25519_publkey.bytes),
            RPACKET_ENCODE);

    mutka_rpacket_add_ent(&client->out_raw_packet,
            "public_mlkem",
            client->msg_keys.mlkem_publkey.bytes,
            sizeof(client->msg_keys.mlkem_publkey.bytes),
            RPACKET_ENCODE);

    mutka_send_encrypted_rpacket(
            client->socket_fd,
            &client->out_raw_packet,
            &client->mtdata_keys.hshared_key);
}

void mutka_send_message(struct mutka_client* client, char* message, size_t message_len) {
   
    if((client->flags & MUTKA_CLFLG_SENDING_MSG)) {
        printf("%s: Previous message is still being sent...\n",__func__);
        return; // Previous message is still being sent...
    }

    client->num_peer_msg_keys = 0;
    mutka_rpacket_prep(&client->out_raw_packet, MPACKET_GET_PEER_PUBLKEYS);
    mutka_send_encrypted_rpacket(
            client->socket_fd,
            &client->out_raw_packet,
            &client->mtdata_keys.hshared_key);


    mutka_str_move(&client->plaintext_msg, message, message_len);
}


