
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "../../../libmutka/include/mutka.h"
#include "../../../libmutka/include/cryptography.h"

/*
#include <openssl/rand.h>


int main() {


    char plain_data[] = "Hello AES GCM Mode!";
    size_t plain_data_size = strlen(plain_data);

    printf("%s\n", plain_data);
   
    char gcm_key[32] = { 0 };
    char gcm_iv[16] = { 0 };
    
    RAND_bytes((uint8_t*)gcm_key, 32);
    RAND_bytes((uint8_t*)gcm_iv, 16);

    char* gcm_aad = "asdasdsahg";

    struct mutka_str cipher;
    struct mutka_str tag;
    
    mutka_str_alloc(&cipher);
    mutka_str_alloc(&tag);

    if(!mutka_openssl_AES256GCM_encrypt(
                &cipher,
                &tag,
                gcm_key,
                gcm_iv,
                gcm_aad, strlen(gcm_aad),
                plain_data, plain_data_size
                )) {
        printf("%s\n", mutka_get_errmsg());
        goto fail;
    }


    mutka_dump_strbytes(&cipher, "cipher");



    // ---------------------------------------


    struct mutka_str plaintext;
    mutka_str_alloc(&plaintext);

    if(!mutka_openssl_AES256GCM_decrypt(
                &plaintext,
                gcm_key,
                gcm_iv,
                gcm_aad, strlen(gcm_aad),
                tag.bytes, tag.size,
                cipher.bytes, cipher.size
                )) {
        printf("Failed to decrypt.\n");
    }
    else {
        printf("%s\n", plaintext.bytes);
    }
    

    mutka_str_free(&plaintext);

fail:

    mutka_str_free(&cipher);
    mutka_str_free(&tag);


    return 0;
}
*/



void mutka_error(char* buffer, size_t size) {
    (void)size;
    printf("[libmutka error]: %s\n", buffer);
}



void packet_received(struct mutka_client* client) {
   
    printf("\033[32m%s\033[0m\n", __func__);

    for(uint32_t i = 0; i < client->inpacket.num_elements; i++) {
        struct mutka_packet_elem* elem = &client->inpacket.elements[i];
        printf("[%i] -> %s:%s\n", i, elem->label.bytes, elem->data.bytes);
    }

}


int main(int argc, char** argv) {
    if(argc < 2) {
        fprintf(stderr, "No nickname. Usage: %s <nickname>\n", argv[0]);
        return 1;
    }
    char* nickname = argv[1];
    
    mutka_set_errmsg_callback(mutka_error);


    struct mutka_client_cfg config = 
    (struct mutka_client_cfg)
    {
        .use_default_cfgdir = true // Use "/home/user/.mutka/"
    };


    // Copy nickname for configuration.
    size_t nickname_len = strlen(nickname);
    if(nickname_len >= MUTKA_NICKNAME_MAX) {
        fprintf(stderr, "Too long nickname. max length is %i\n", MUTKA_NICKNAME_MAX);
        return 1;
    }

    memmove(config.nickname, nickname, nickname_len);


    if(!mutka_validate_client_cfg(&config)) {
        return 1;
    }
 
    // If the client doesnt own "trusted-keys" for the nickname.
    // Ask to generate them with user chosen passphase.
    // That passphase is going to be used to decrypt the trusted private key.
    // The trusted private key is used for authentication between clients.
    if(!mutka_cfg_trustedkeys_exists(&config)) {
        printf("\033[33mYour trusted-key was not found for nickname \"%s\"\n"
                "Would you like to generate it? (yes/no): \033[0m",
                nickname);
        fflush(stdout);

        char input[8] = { 0 };
        read(STDIN_FILENO, input, sizeof(input));
        if((input[0] != 'Y') && (input[0] != 'y')) {
            return 1;
        }

        printf("Enter passphase for trusted-key: ");
        fflush(stdout);
        char passphase[512] = { 0 };
        size_t passphase_len = read(STDIN_FILENO, passphase, sizeof(passphase));

        if(mutka_cfg_generate_trustedkeys(&config, passphase, passphase_len)) {
            printf("\033[32mYour trusted-keys are generated.\n"
                    "You should now add your peer's\ntrusted-key public key"
                    " into '%s'\033[0m\n", config.trusted_peers_dir);
        }

        memset(passphase, 0, sizeof(passphase));


        return 0;
    }



    // At this point the client_config should have the trusted_privkey_path assigned.
    // Now it must be decrypted before use.
    // The same passphase is needed here, when the trusted-keys were generated.

    printf("Enter passphase for trusted-key: ");
    fflush(stdout);
    char passphase[512] = { 0 };
    size_t passphase_len = read(STDIN_FILENO, passphase, sizeof(passphase));

    if(!mutka_decrypt_trusted_privkey(&config, passphase, passphase_len)) {
        return 1;
    }

    if(!mutka_read_trusted_publkey(&config)) {
        return 1;
    }


    // Finally should be able to connect.

    struct mutka_client* client = mutka_connect(&config, "127.0.0.1", 35580);
    if(!client) {
        return 1;
    }

    client->packet_received_callback = packet_received;


    printf("press enter to disconnect.\n");

    char tmp = 0;
    read(1, &tmp, 1);

    mutka_disconnect(client);
    printf("disconnected.\n");
    return 0;
}




