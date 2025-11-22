#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <openssl/rand.h>

#define MUTKA_CLIENT
#include "../include/client.h"
#include "../include/mutka.h"


#define CLIENT_PRIVATE_IDENTITY_FILE_HEADER "libmutka-client_private-identity"



// TODO: Move this away from here...
static struct client_global {
    
    pthread_t recv_thread;

}
global;


void* mutka_client_recv_thread(void* arg);

void mutka_client_handle_packet(struct mutka_client* client);


#include <stdio.h>


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

bool mutka_read_public_identity(struct mutka_client_cfg* config) {
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
    config->flags |= MUTKA_CCFLG_HAS_IDENTITY_KEYS;

unmap_and_out:
    munmap(file_data, file_size);
    mutka_str_free(&privkey_cipher);
    mutka_str_free(&derived_key);
    mutka_str_free(&decrypted_privkey);

out:
    return result;
}




struct mutka_client* mutka_connect
(
    struct mutka_client_cfg* config,
    char* host,
    char* port
){
    struct mutka_client* client = NULL;

    if(!(config->flags & MUTKA_CCFLG_HAS_IDENTITY_KEYS)) {
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
    pthread_mutex_init(&client->mutex, NULL);

    // Copy host address for future use.
    client->host_addr_len = strlen(host);
    if(client->host_addr_len >= MUTKA_HOST_ADDR_MAX) {
        mutka_set_errmsg("Host address is too long");
        goto out;
    }
    memset(client->host_addr, 0, sizeof(client->host_addr));
    memcpy(client->host_addr, host, client->host_addr_len);

    // Copy host port for future use.
    client->host_port_len = strlen(port);
    if(client->host_port_len >= MUTKA_HOST_PORT_MAX) {
        mutka_set_errmsg("Host port is too long");
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
        mutka_free_rpacket(&client->out_raw_packet);
        mutka_free_packet(&client->inpacket);
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

void mutka_client_handle_packet(struct mutka_client* client) {
    // NOTE: client->mutex is locked here.

    printf("%s: (packet id = %i)\n", __func__, client->inpacket.id);

    // NOTE: Remember to return from switch statement instead of break
    //       if handling internal packets.

    // TODO: Create better system to handle packet element sizes

    // Check for internal packets first.
    switch(client->inpacket.id) {

        case MPACKET_GET_CLIENTS:
            {
                printf("MPACKET_GET_CLIENTS: %i\n", client->inpacket.num_elements);
            }
            return;

        case MPACKET_TEST:
            printf("%s\n", client->inpacket.elements[0].data.bytes);
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
                struct mutka_packet_elem* mlkem_wrapped_elem     = &client->inpacket.elements[1];
                struct mutka_packet_elem* signature_elem         = &client->inpacket.elements[2];
                struct mutka_packet_elem* hkdf_salt_elem         = &client->inpacket.elements[3];

                uint8_t  hkdf_salt [HKDF_SALT_LEN] = { 0 };

                signature_mldsa87_t signature;
                key128bit_t         peer_x25519_publkey;
                uint8_t             mlkem_wrapped [mutka_get_decoded_buffer_len(mlkem_wrapped_elem->data.size)];

                if(!mutka_decode(peer_x25519_publkey.bytes, sizeof(peer_x25519_publkey.bytes),
                            peer_x25519_elem->data.bytes,
                            peer_x25519_elem->data.size)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: "
                            "Failed to decode peer X25519 public key.");
                    client->flags |= MUTKA_CLFLG_SHOULD_DISCONNECT;
                    return;
                }

                if(!mutka_decode(mlkem_wrapped, sizeof(mlkem_wrapped),
                            mlkem_wrapped_elem->data.bytes,
                            mlkem_wrapped_elem->data.size)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: "
                            "Failed to decode wrapped ML-KEM-1024 key.");
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

                //MUTKA_HEX_DUMP(client->host_mldsa87_publkey, "HOST PUBLKEY");

                // Server combines X25519 public key hash + wrapped ML-KEM-1024 key hash.
                // and it is used as data for signature.
                uint8_t peer_keys_combined_hash[SHA512_DIGEST_LENGTH * 2] = { 0 };

                SHA512(peer_x25519_publkey.bytes,
                        sizeof(peer_x25519_publkey.bytes),
                        peer_keys_combined_hash);

                SHA512(mlkem_wrapped,
                        sizeof(mlkem_wrapped),
                        peer_keys_combined_hash + SHA512_DIGEST_LENGTH);

                if(!mutka_openssl_MLDSA87_verify(
                            MUTKA_VERSION_STR"(METADATAKEYS_SIGN_FROM_SERVER)",
                            &signature,
                            &client->host_mldsa87_publkey,
                            peer_keys_combined_hash,
                            sizeof(peer_keys_combined_hash))) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: Cant verify host keys.");
                    client->flags |= MUTKA_CLFLG_SHOULD_DISCONNECT;
                    return;
                }

                key128bit_t x25519_shared_secret;
                key128bit_t mlkem_shared_secret;


                if(!mutka_openssl_derive_shared_secret(
                            &x25519_shared_secret,
                            &client->mtdata_keys.x25519_privkey,
                            &peer_x25519_publkey)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: Failed to derive shared X25519 secret.");
                    client->flags |= MUTKA_CLFLG_SHOULD_DISCONNECT;
                    return;
                }
                

                // Get mlkem shared secret.
                if(!mutka_openssl_decaps(
                            &mlkem_shared_secret,
                            mlkem_wrapped,
                            sizeof(mlkem_wrapped),
                            &client->mtdata_keys.mlkem_privkey)) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: Failed to decapsulate ML-KEM-1024 key.");
                    client->flags |= MUTKA_CLFLG_SHOULD_DISCONNECT;
                    return;
                }

              
                // Get hybrid shared key.

                uint8_t hybrid_secret[sizeof(x25519_shared_secret.bytes) + sizeof(mlkem_shared_secret.bytes)] = { 0 };
                memmove(hybrid_secret,
                        x25519_shared_secret.bytes,
                        sizeof(x25519_shared_secret.bytes));

                memmove(hybrid_secret + sizeof(x25519_shared_secret.bytes),
                        mlkem_shared_secret.bytes,
                        sizeof(mlkem_shared_secret.bytes));

                if(!mutka_openssl_HKDF(
                            &client->mtdata_keys.hshared_key,
                            hybrid_secret,
                            sizeof(hybrid_secret),
                            hkdf_salt,
                            MUTKA_VERSION_STR"(METADATAKEYS_HYBRIDKEY_HKDF)")) {
                    mutka_set_errmsg("MPACKET_EXCHANGE_METADATA_KEYS: Failed to derive shared hybrid key.");
                    client->flags |= MUTKA_CLFLG_SHOULD_DISCONNECT;
                    return;
                }


                printf("\033[32mMetadata key exchange with host is complete.\033[0m\n");

                // Inform the server everything is ok and we can continue.
                mutka_rpacket_prep(&client->out_raw_packet, MPACKET_METADATA_KEY_EXHCANGE_COMPLETE);
                mutka_send_clear_rpacket(client->socket_fd, &client->out_raw_packet);
            }
            return;

        case MPACKET_METADATA_KEY_EXHCANGE_COMPLETE:
            mutka_gen_new_msgkeys(client);
            return;
    }

    client->packet_received_callback(client);
}

void mutka_gen_new_msgkeys(struct mutka_client* client) {
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


    mutka_rpacket_prep(&client->out_raw_packet, MPACKET_GET_CLIENTS);
    mutka_send_encrypted_rpacket(
            client->socket_fd,
            &client->out_raw_packet,
            &client->mtdata_keys.hshared_key);

    printf("%s\n", __func__);

}


