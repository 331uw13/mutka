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

    config->flags = 0;

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



    // Go back to config directory.
    mutka_str_move(&tmpdir, config->mutka_cfgdir, cfgdir_length);
    
    // Construct trusted_publkey_path.
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
    bool result = false;

    if(passphase_len < 8) {
        mutka_set_errmsg("Trusted private key passphase should NOT be less than 8 characters long.");
        goto out;
    }

    // 'trusted_peers_dir' should contain 'mutka_cfgdir' as parent directory.
    if(!mutka_mkdir_p(config->trusted_peers_dir, S_IRWXU)) {
        goto out;
    }

    if(!mutka_file_exists(config->trusted_privkey_path)) {
        if(creat(config->trusted_privkey_path, S_IRUSR | S_IWUSR) < 0) {
            mutka_set_errmsg("Failed to create trusted"
                    " private key file | %s", strerror(errno));
            goto out;
        }
    }

    if(!mutka_file_exists(config->trusted_publkey_path)) {
        if(creat(config->trusted_publkey_path, S_IRUSR | S_IWUSR) < 0) {
            mutka_set_errmsg("Failed to create trusted"
                    " public key file | %s", strerror(errno));
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


struct mutka_client* mutka_connect(struct mutka_client_cfg* config) {
    struct mutka_client* client = NULL;

    if(!(config->flags & MUTKA_CCFG_HAS_TRUSTED_PUBLKEY)) {
        mutka_set_errmsg("Client configuration doesnt contain trusted PUBLIC key.");
        goto out;
    }

    if(!(config->flags & MUTKA_CCFG_HAS_TRUSTED_PRIVKEY)) {
        mutka_set_errmsg("Client configuration doesnt contain trusted PRIVATE key.");
        goto out;
    }

    client = malloc(sizeof *client);
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

    // Initialize client structure.
    client->inpacket.elements = NULL;
    client->inpacket.num_elements = 0;
    mutka_alloc_rpacket(&client->out_raw_packet, MUTKA_RAW_PACKET_DEFMEMSIZE);
    mutka_alloc_rpacket(&client->inpacket.raw_packet, MUTKA_RAW_PACKET_DEFMEMSIZE);

    client->handshake_complete = false;
    client->metadata_keys = mutka_init_keypair();

    mutka_str_alloc(&client->peer_metadata_publkey);
    mutka_openssl_X25519_keypair(&client->metadata_keys);

    mutka_dump_strbytes(&client->metadata_keys.public_key, "my metadata publkey");

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
            printf("lost connection | TODO: handle this\n");
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

            mutka_dump_strbytes(&client->inpacket.elements[0].data, "peer metadata publkey");

            client->handshake_complete = true;
            return;
    }

    client->packet_received_callback(client);
}


