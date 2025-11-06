#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <openssl/rand.h>

#include "../include/client.h"
#include "../include/mutka.h"



static struct client_global {
    
    pthread_t recv_thread;

}
global;


void* mutka_client_recv_thread(void* arg);
void mutka_client_handle_packet(struct mutka_client* client);


#include <stdio.h>


static bool mutka_add_config_file
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

static bool mutka_add_config_dir
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


bool mutka_validate_client_cfg(struct mutka_client_cfg* config, char* nickname) {
    bool result = false;

    if(!config->add_new_trusted_host_callback) {
        mutka_set_errmsg("\"add_new_trusted_host_callback\" is missing.");
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
           |- username123.public_key
           |- username123.private_key (encrypted)
           '- trusted_peers/
              |- friend_A.public_key
              '- friend_B.public_key
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


    if(!mutka_add_config_dir(&cfg_root, &cfg_root_tmp, config->trusted_peers_dir, "trusted_peers")) {
        goto free_and_out;
    }

    if(!mutka_add_config_file(&cfg_root, &cfg_root_tmp, config->trusted_privkey_path,
                nickname, nickname_len, ".private_key")) {
        goto free_and_out;
    }
    
    if(!mutka_add_config_file(&cfg_root, &cfg_root_tmp, config->trusted_publkey_path,
                nickname, nickname_len, ".public_key")) {
        goto free_and_out;
    }
    
    if(!mutka_add_config_file(&cfg_root, &cfg_root_tmp, config->trusted_hosts_path,
                nickname, nickname_len, ".trusted_hosts")) {
        goto free_and_out;
    }

    printf("mutka_cfgdir         = '%s'\n", config->mutka_cfgdir);
    printf("trusted_peers_dir    = '%s'\n", config->trusted_peers_dir);
    printf("trusted_privkey_path = '%s'\n", config->trusted_privkey_path);
    printf("trusted_publkey_path = '%s'\n", config->trusted_publkey_path);
    printf("trusted_hosts_path   = '%s'\n", config->trusted_hosts_path);
    printf("nickname             = '%s'\n", config->nickname);
    result = true;

free_and_out:
    mutka_str_free(&cfg_root);
    mutka_str_free(&cfg_root_tmp);

out:
    return result;
}

bool mutka_cfg_trustedkeys_exists(struct mutka_client_cfg* config) {

    size_t publkey_file_size = 0;
    size_t privkey_file_size = 0;

    if(mutka_file_exists(config->trusted_publkey_path)) {
        mutka_map_file(config->trusted_publkey_path, NULL, &publkey_file_size);
    }

    if(mutka_file_exists(config->trusted_privkey_path)) {
        mutka_map_file(config->trusted_privkey_path, NULL, &privkey_file_size);
    }

    // The private key is encrypted so
    // it should have more bytes than just 'key length'
    return (publkey_file_size >= ED25519_KEYLEN) && (privkey_file_size > ED25519_KEYLEN);
}

bool mutka_cfg_generate_trustedkeys(struct mutka_client_cfg* config,
        char* privkey_passphase, size_t passphase_len) {
    bool result = false;

    if(passphase_len < 8) {
        mutka_set_errmsg("Trusted private key passphase should NOT be less than 8 characters long.");
        goto out;
    }

    if(!mutka_mkdir_p(config->trusted_peers_dir, S_IRWXU)) {
        goto out;
    }

    if(!mutka_file_exists(config->trusted_privkey_path)) {
        if(creat(config->trusted_privkey_path, S_IRUSR | S_IWUSR) < 0) {
            mutka_set_errmsg("Failed to create trusted"
                    " private key file \"%s\" | %s", config->trusted_privkey_path, strerror(errno));
            goto out;
        }
    }

    if(!mutka_file_exists(config->trusted_publkey_path)) {
        if(creat(config->trusted_publkey_path, S_IRUSR | S_IWUSR) < 0) {
            mutka_set_errmsg("Failed to create trusted"
                    " public key file \"%s\" | %s", config->trusted_publkey_path, strerror(errno));
            goto out;
        }
    }


    struct mutka_keypair trusted_keys = mutka_init_keypair();
    if(!mutka_openssl_ED25519_keypair(&trusted_keys)) {
        mutka_free_keypair(&trusted_keys);
        goto out;
    }


    // Use scrypt to derieve stronger and more suitable key for AES.
    // It will be used to encrypt the ED25519 private key.

    struct mutka_str derived_key;
    mutka_str_alloc(&derived_key);

    char scrypt_salt[SCRYPT_SALT_LEN] = { 0 };
    RAND_bytes((uint8_t*)scrypt_salt, sizeof(scrypt_salt));

    mutka_openssl_scrypt(
            &derived_key, 
            32, // Output size
            privkey_passphase, passphase_len,
            scrypt_salt, sizeof(scrypt_salt));


    struct mutka_str privkey_cipher;
    mutka_str_alloc(&privkey_cipher);

    char gcm_iv[AESGCM_IV_LEN] = { 0 };
    RAND_bytes((uint8_t*)gcm_iv, sizeof(gcm_iv));

    struct mutka_str gcm_tag;
    mutka_str_alloc(&gcm_tag);

    if(!mutka_openssl_AES256GCM_encrypt(
            &privkey_cipher,
            &gcm_tag,
            derived_key.bytes,
            gcm_iv,
            MUTKA_VERSION_STR, strlen(MUTKA_VERSION_STR),
            trusted_keys.private_key.bytes,
            trusted_keys.private_key.size)) {
        mutka_set_errmsg("Failed to encrypt trusted private key.");
        goto free_and_out;
    }

    /*
    mutka_dump_strbytes(&privkey_cipher, "privkey_cipher");
    mutka_dump_bytes(scrypt_salt, sizeof(scrypt_salt), "scrypt_salt"); 
    mutka_dump_bytes(gcm_iv, sizeof(gcm_iv), "gcm_iv");
    mutka_dump_strbytes(&gcm_tag, "gcm_tag");
    mutka_dump_strbytes(&derived_key, "derived_key");
    mutka_dump_bytes(privkey_passphase, passphase_len, "passphase");
    */
    // Save information for decryption process: 
    /*
       [scrypt_salt]    (SCRYPT_SALT_LEN)
       [cipher_length]  (4 bytes)
       [cipher]         (cipher_length)
       [iv]             (AESGCM_IV_LEN)
       [tag]            (AESGCM_TAG_LEN)
       [aad]            (variable length until EOF)
    */

    mutka_file_clear(config->trusted_privkey_path);


    
    if(!mutka_file_append(config->trusted_privkey_path, scrypt_salt, sizeof(scrypt_salt))) {
        mutka_set_errmsg("Failed to save trusted private key's scrypt salt.");
        goto free_and_out;
    }

    if(!mutka_file_append(config->trusted_privkey_path, (char*)&privkey_cipher.size, sizeof(privkey_cipher.size))) {
        mutka_set_errmsg("Failed to save trusted private key's cipher length.");
        goto free_and_out;
    }

    if(!mutka_file_append(config->trusted_privkey_path, privkey_cipher.bytes, privkey_cipher.size)) {
        mutka_set_errmsg("Failed to save trusted private key's cipher.");
        goto free_and_out;
    }

    if(!mutka_file_append(config->trusted_privkey_path, gcm_iv, sizeof(gcm_iv))) {
        mutka_set_errmsg("Failed to save trusted private key's AES GCM IV.");
        goto free_and_out;
    }

    if(!mutka_file_append(config->trusted_privkey_path, gcm_tag.bytes, gcm_tag.size)) {
        mutka_set_errmsg("Failed to save trusted private key's AES GCM TAG.");
        goto free_and_out;
    }

    if(!mutka_file_append(config->trusted_privkey_path, MUTKA_VERSION_STR, strlen(MUTKA_VERSION_STR))) {
        mutka_set_errmsg("Failed to save trusted private key's AES GCM AAD.");
        goto free_and_out;
    }



    // Save trusted public key
    
    mutka_file_clear(config->trusted_publkey_path); 
    if(!mutka_file_append(config->trusted_publkey_path,
                trusted_keys.public_key.bytes, trusted_keys.public_key.size)) {
        mutka_set_errmsg("Failed to save trusted public key.");
        goto free_and_out;
    }

    result = true;

free_and_out:

    mutka_str_clear(&derived_key);
    mutka_str_free(&derived_key);
    mutka_str_free(&privkey_cipher);
    mutka_free_keypair(&trusted_keys);

out:
    return result;
}

bool mutka_read_trusted_publkey(struct mutka_client_cfg* config) {
    bool result = false;

    char* publkey_file = NULL;
    size_t publkey_file_size = 0;

    if(!mutka_map_file(config->trusted_publkey_path, &publkey_file, &publkey_file_size)) {
        goto out;
    }
    if(publkey_file_size == 0) {
        mutka_set_errmsg("Trusted public key file is empty.");
        goto out;
    }

    if(publkey_file_size != sizeof(config->trusted_publkey)) {
        mutka_set_errmsg("Unexpected trusted public key size: %li", publkey_file_size);
        goto free_and_out;
    }

    memmove(config->trusted_publkey, publkey_file, sizeof(config->trusted_publkey));
    config->flags |= MUTKA_CCFG_HAS_TRUSTED_PUBLKEY;

free_and_out:

    munmap(publkey_file, publkey_file_size);
    result = true;

out:

    return result;
}

bool mutka_decrypt_trusted_privkey
(
    struct mutka_client_cfg* config,
    char* passphase, size_t passphase_len
){
    bool result = false;

    char* privkey_file = NULL;
    size_t privkey_file_size = 0;

    if(!mutka_map_file(config->trusted_privkey_path, &privkey_file, &privkey_file_size)) {
        goto out;
    }

    // TODO: IMPORTANT! Should expect a size and not just follow trough if its "not empty"
    // ----------------------------------------------------------------------------------

    if(privkey_file_size == 0) {
        mutka_set_errmsg("Trusted private key file is empty.");
        goto out;
    }

    /*
       Trusted private key file structure:

       [scrypt_salt]    (SCRYPT_SALT_LEN)
       [cipher_length]  (4 bytes)
       [cipher]         (cipher_length)
       [iv]             (AESGCM_IV_LEN)
       [tag]            (AESGCM_TAG_LEN)
       [aad]            (variable length until EOF)
    */


    struct mutka_str private_key;
    struct mutka_str key_cipher;
    struct mutka_str gcm_aad;
    struct mutka_str derived_key;
    mutka_str_alloc(&derived_key);
    mutka_str_alloc(&key_cipher);
    mutka_str_alloc(&gcm_aad);
    mutka_str_alloc(&private_key);

    char gcm_iv[AESGCM_IV_LEN] = { 0 };
    char gcm_tag[AESGCM_TAG_LEN] = { 0 };
    char scrypt_salt[SCRYPT_SALT_LEN] = { 0 };

    size_t byte_offset = 0;


    
    // Read scrypt salt.
    memmove(scrypt_salt, &privkey_file[byte_offset], sizeof(scrypt_salt));
    byte_offset += sizeof(scrypt_salt);
    if(byte_offset >= privkey_file_size) {
        mutka_set_errmsg("Unexpected EOF (reading scrypt salt).");
        goto free_and_out;
    }
    
    // Read cipher length.
    int cipher_length = 0;
    memmove(&cipher_length, &privkey_file[byte_offset], sizeof(cipher_length));
    byte_offset += sizeof(cipher_length);
    if(byte_offset >= privkey_file_size) {
        mutka_set_errmsg("Unexpected EOF (reading key cipher length).");
        goto free_and_out;
    }

    // Read key cipher.
    mutka_str_reserve(&key_cipher, cipher_length);
    mutka_str_move(&key_cipher, &privkey_file[byte_offset], cipher_length);
    byte_offset += cipher_length;
    if(byte_offset >= privkey_file_size) {
        mutka_set_errmsg("Unexpected EOF (reading key cipher).");
        goto free_and_out;
    }

    // Read GCM IV.
    memmove(gcm_iv, &privkey_file[byte_offset], sizeof(gcm_iv));
    byte_offset += sizeof(gcm_iv);
    if(byte_offset >= privkey_file_size) {
        mutka_set_errmsg("Unexpected EOF (reading GCM IV).");
        goto free_and_out;
    }

    // Read GCM TAG.
    memmove(gcm_tag, &privkey_file[byte_offset], sizeof(gcm_tag));
    byte_offset += sizeof(gcm_tag);
    if(byte_offset >= privkey_file_size) {
        mutka_set_errmsg("Unexpected EOF (reading GCM TAG).");
        goto free_and_out;
    }

    // Read GCM AAD.
    const int64_t remaining = privkey_file_size - byte_offset;
    if(remaining < 0) {
        mutka_set_errmsg("Unexpected EOF (reading GCM AAD).");
        goto free_and_out;
    }
    mutka_str_reserve(&gcm_aad, remaining);
    mutka_str_move(&gcm_aad, &privkey_file[byte_offset], remaining);


    // Get key for decrypting.
    mutka_openssl_scrypt(
            &derived_key, 
            32, // Output key size
            passphase, passphase_len,
            scrypt_salt, sizeof(scrypt_salt));
    

    // Now all information should be collected
    // to decrypt the trusted private key.
    /*
    mutka_dump_strbytes(&key_cipher, "key_cipher");
    mutka_dump_bytes(scrypt_salt, sizeof(scrypt_salt), "scrypt_salt"); 
    mutka_dump_bytes(gcm_iv, sizeof(gcm_iv), "gcm_iv");
    mutka_dump_bytes(gcm_tag, sizeof(gcm_tag), "gcm_tag");
    mutka_dump_strbytes(&derived_key, "derived_key");
    mutka_dump_bytes(passphase, passphase_len, "passphase");
    */
    if(!mutka_openssl_AES256GCM_decrypt(
                &private_key,
                derived_key.bytes,
                gcm_iv,
                gcm_aad.bytes, gcm_aad.size,
                gcm_tag, AESGCM_TAG_LEN,
                key_cipher.bytes, key_cipher.size)) {
        mutka_set_errmsg("Failed to decrypt trusted private key.");
        goto free_and_out;
    }
    
    if(private_key.size != ED25519_KEYLEN) {
        mutka_set_errmsg("Unexpected trusted private key size: %i", private_key.size);
        goto free_and_out;
    }

    
    memmove(config->trusted_privkey, private_key.bytes, sizeof(config->trusted_privkey));
    config->flags |= MUTKA_CCFG_HAS_TRUSTED_PRIVKEY;
    result = true;

free_and_out:

    mutka_str_clear(&private_key);
    mutka_str_free(&private_key);
    mutka_str_free(&derived_key);
    mutka_str_free(&key_cipher);
    mutka_str_free(&gcm_aad);
    munmap(privkey_file, privkey_file_size);

out:
    return result;
}


struct mutka_client* mutka_connect(struct mutka_client_cfg* config, char* host, char* port) {
    struct mutka_client* client = NULL;

    if(!(config->flags & MUTKA_CCFG_HAS_TRUSTED_PUBLKEY)) {
        mutka_set_errmsg("Client configuration doesnt contain trusted PUBLIC key.");
        goto out;
    }

    if(!(config->flags & MUTKA_CCFG_HAS_TRUSTED_PRIVKEY)) {
        mutka_set_errmsg("Client configuration doesnt contain trusted PRIVATE key.");
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
    client->inpacket.elements = NULL;
    client->inpacket.num_elements = 0;
    mutka_alloc_rpacket(&client->out_raw_packet, MUTKA_RAW_PACKET_DEFMEMSIZE);
    mutka_alloc_rpacket(&client->inpacket.raw_packet, MUTKA_RAW_PACKET_DEFMEMSIZE);

    client->handshake_complete = false;
    client->metadata_keys = mutka_init_keypair();
    mutka_str_alloc(&client->peer_metadata_publkey);

    // Create thread for receiving data.
    pthread_create(&global.recv_thread, NULL, mutka_client_recv_thread, client);
  
    mutka_init_metadata_key_exchange(client);

out:
    return client;
}


void mutka_init_metadata_key_exchange(struct mutka_client* client) {
    mutka_openssl_X25519_keypair(&client->metadata_keys);

    mutka_dump_strbytes(&client->metadata_keys.public_key, "my metadata publkey");
    
    // Initiate handshake by sending generated metadata public key.
    // see packet.h for more information about metadata keys.
    mutka_rpacket_prep(&client->out_raw_packet, MPACKET_EXCHANGE_METADATA_KEYS);
    mutka_rpacket_add_ent(&client->out_raw_packet, 
            "metadata_publkey", 
            client->metadata_keys.public_key.bytes, 
            client->metadata_keys.public_key.size,
            RPACKET_ENCODE_BASE64);
    
    mutka_send_rpacket(client->socket_fd, &client->out_raw_packet);
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
    printf("%s: started\n",__func__);

    struct mutka_client* client = (struct mutka_client*)arg;
    while(true) {
        pthread_mutex_lock(&client->mutex);

        int rd = mutka_recv_incoming_packet(&client->inpacket, client->socket_fd);
   
        if(rd == M_NEW_PACKET_AVAIL) {
            mutka_client_handle_packet(client);
            printf("M_NEW_PACKET_AVAIL\n");
        }
        else
        if(rd == M_LOST_CONNECTION) {
            printf("lost connection | TODO: handle this\n");
        }
        else
        if(rd == M_PACKET_PARSE_ERR) {
            printf("M_PACKET_PARSE_ERR\n");
        }

        pthread_mutex_unlock(&client->mutex);
        mutka_sleep_ms(1); // Small delay to limit CPU usage.
    }

    return NULL;
}


static bool mutka_client_save_host_public_key
(
    struct mutka_client* client,
    struct mutka_str* public_key,
    char* host_tag
){
    bool result = false;

    // We should first ask to save it or not.
    bool can_add = client->config.add_new_trusted_host_callback(client, &client->inpacket.elements[0].data);
   
    if(!can_add) {
        goto out;
    }

    char buffer[512] = { 0 };
    const size_t buffer_len = snprintf(buffer, sizeof(buffer)-1, "%s%s",
            host_tag,
            public_key->bytes);

    printf("%s: %s\n", __func__, buffer);

    if(!mutka_file_append(client->config.trusted_hosts_path, buffer, buffer_len)) {
        mutka_set_errmsg("Failed to save trusted host to \"%s\"", client->config.trusted_hosts_path);
        goto out;
    }

    result = true;

out:
    return result;
}

// Process received host ed25519 public key.
static bool mutka_client_process_recv_host_key(struct mutka_client* client) {
    bool result = false;

    struct mutka_str* recv_host_publkey = &client->inpacket.elements[0].data;
    printf("(%i) recv host ed25519 public key: %s\n", recv_host_publkey->size, recv_host_publkey->bytes);


    // "host_addr#host_port:"
    char host_tag[128] = { 0 };
    const size_t host_tag_len = snprintf(host_tag, sizeof(host_tag)-1, 
            "%s#%s:", client->host_addr, client->host_port);

    char* trusted_hosts_file = NULL;
    size_t trusted_hosts_file_size = 0;

    if(!mutka_map_file(client->config.trusted_hosts_path, &trusted_hosts_file, &trusted_hosts_file_size)) {
        goto out;
    }

    // Try to find 'host_tag' from the saved trusted hosts file.
    ssize_t host_index = mutka_charptr_find(
            trusted_hosts_file, 
            trusted_hosts_file_size,
            host_tag,
            host_tag_len);

    if(host_index < 0) {
        // 'host_tag' was not found.
        if(!mutka_client_save_host_public_key(client, recv_host_publkey, host_tag)) {
            goto unmap_and_out;
        }
    }
    else {
        // Key should exist, compare it to expected value.

        host_index += host_tag_len;

        if(host_index >= trusted_hosts_file_size) {
            mutka_set_errmsg("Something went wrong when tried to find saved host public key from file. "
                    "(host_index >= trusted_hosts_file_size)");
            goto unmap_and_out;
        }

        for(size_t i = host_index; i < trusted_hosts_file_size; i++) {

            const char expected_publkey_byte = recv_host_publkey->bytes[i - host_index];
            const char saved_publkey_byte = trusted_hosts_file[i];

            if(expected_publkey_byte != saved_publkey_byte) {
                fprintf(stderr, "\033[31m\033[1m WARNING: HOST SIGNATURE KEYS HAVE CHANGED!\033[0m\n");
                goto unmap_and_out;
            }
        }
        printf("\033[32mHost key matched\033[0m\n");

    }

    result = true;

unmap_and_out:
    munmap(trusted_hosts_file, trusted_hosts_file_size);

out:
    return result;
}

void mutka_client_handle_packet(struct mutka_client* client) {
    // NOTE: client->mutex is locked here.

    printf("%s: (packet id = %i)\n", __func__, client->inpacket.id);

    // NOTE: Remember to return from switch statement instead of break
    //       if handling internal packets.

    // TODO: Create better system to handle packet element sizes

    // Check for internal packets first.
    switch(client->inpacket.id) {
        case MPACKET_HOST_PUBLIC_KEY: 
            if(client->inpacket.num_elements != 1) {
                mutka_set_errmsg("Failed to receive host public key.");
                return;
            }

            mutka_client_process_recv_host_key(client);
            return;

        case MPACKET_EXCHANGE_METADATA_KEYS:
            if(client->handshake_complete) {
                // TODO: REMOVE THIS
                mutka_set_errmsg("Handshake has already been complete.");
                return;
            }

            if(client->inpacket.num_elements != 1) {
                mutka_set_errmsg("Failed to receive handshake packet.");
                return;
            }

            mutka_openssl_BASE64_decode(
                    &client->peer_metadata_publkey,
                    client->inpacket.elements[0].data.bytes,
                    client->inpacket.elements[0].data.size);

            mutka_dump_strbytes(&client->peer_metadata_publkey, "peer metadata publkey");

            client->handshake_complete = true;
            return;
    }

    client->packet_received_callback(client);
}


