#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#define MUTKA_CLIENT
#include "../../../libmutka/include/mutka.h"

#include "../../../libmutka/include/cryptography.h"



void mutka_error(char* buffer, size_t size) {
    (void)size;
    printf("[libmutka error]: %s\n", buffer);
}


// Mutex is used for reading input because the main thread requires input as well.
// Otherwise both will get the same input...
static pthread_mutex_t stdin_read_mutex;


char read_user_input_yes_or_no() {
    pthread_mutex_lock(&stdin_read_mutex);

    char input[8] = { 0 };
    read(STDIN_FILENO, input, sizeof(input));

    pthread_mutex_unlock(&stdin_read_mutex);

    return input[0];
}


void packet_received(struct mutka_client* client) {
    printf("\033[32m%s\033[0m\n", __func__);
    for(uint32_t i = 0; i < client->inpacket.num_elements; i++) {
        struct mutka_packet_elem* elem = &client->inpacket.elements[i];
        printf("[%i] -> %s:%s\n", i, elem->label.bytes, elem->data.bytes);
    }
}

bool accept_new_trusted_host(struct mutka_client* client, struct mutka_str* host_publkey) {
    printf("Save new trusted host? (yes/no): ");
    fflush(stdout);

    char user_choise = read_user_input_yes_or_no();
    return ((user_choise == 'Y') || (user_choise == 'y'));
}


bool accept_hostkey_change(struct mutka_client* client, struct mutka_str* host_publkey) {
    
    printf("\033[31mWARNING: SERVER PUBLIC KEY HAS CHANGED!\n"
            "Someone may be trying to tamper with the server keys\n"
            "\n"
            "If you choose \"yes\" the old key will be overwritten and connection can continue (may be risky)\n"
            "If you choose \"no\" you will be disconnected\n"
            "\n"
            "Are you really sure you want to continue?\n"
            "(yes/no): \033[0m");
    fflush(stdout);

    char user_choise = read_user_input_yes_or_no();
    return ((user_choise == 'Y') || (user_choise == 'y'));
}


// This function do not require to be blocking.
// mutka_send_captcha_answer() can be called from anywhere.
void confirm_captcha(struct mutka_client* client, char* captcha_buffer) {
    pthread_mutex_lock(&stdin_read_mutex);
    printf("%s\n", captcha_buffer);
    printf("Server requires captcha to be completed.\n"
            "Answer: ");
    fflush(stdout);

    char answer[32] = { 0 };
    read(STDIN_FILENO, answer, sizeof(answer)-1);
    pthread_mutex_unlock(&stdin_read_mutex);

    mutka_send_captcha_answer(client, answer, strlen(answer));
}



int main(int argc, char** argv) {
    
    printf("sizeof(struct mutka_client) = %li\n", sizeof(struct mutka_client));
    
    if(argc < 2) {
        fprintf(stderr, "No nickname. Usage: %s <nickname>\n", argv[0]);
        return 1;
    }
    char* nickname = argv[1];
    
    mutka_set_errmsg_callback(mutka_error);


    struct mutka_client_cfg config = 
    (struct mutka_client_cfg)
    {
        .use_default_cfgdir = true, // "use /home/user/.mutka/"

        .confirm_server_captcha              = confirm_captcha,
        .accept_new_trusted_host_callback    = accept_new_trusted_host,
        .accept_hostkey_change_callback      = accept_hostkey_change
    };

    if(!mutka_validate_client_cfg(&config, nickname)) {
        return 1;
    }


    if(!mutka_client_identity_exists(&config)) {
        printf("\033[33mYour identity-keys was not found for nickname \"%s\"\n"
                "Would you like to generate it? (yes/no): \033[0m",
                nickname);
        fflush(stdout);

        char input[8] = { 0 };
        read(STDIN_FILENO, input, sizeof(input));
        if((input[0] != 'Y') && (input[0] != 'y')) {
            return 1;
        }

        printf("Enter passphase for encrypting private-identity: ");
        fflush(stdout);
        char passphase[512] = { 0 };
        size_t passphase_len = read(STDIN_FILENO, passphase, sizeof(passphase));

        if(mutka_new_client_identity(&config, passphase, passphase_len)) {
            printf("\033[32mYour identity-keys are generated.\033[0m\n");
        }

        memset(passphase, 0, sizeof(passphase));
        return 0;
    }

    printf("Enter passphase for private identity-key: ");
    fflush(stdout);
    char passphase[512] = { 0 };
    size_t passphase_len = read(STDIN_FILENO, passphase, sizeof(passphase));


    if(!mutka_decrypt_client_identity(&config, passphase, passphase_len)) {
        return 1;
    }



    // Finally should be able to connect.

    struct mutka_client* client = mutka_connect(&config, "127.0.0.1", "35580");
    if(!client) {
        return 1;
    }

    client->packet_received_callback = packet_received;



    printf("\033[35mPress [q] then [enter] to disconnect.\n"
                    "Press [r] then [enter] to send message.\033[0m\n");

    // /dev/stdin is opened in nonblocking mode
    // and mutex is used for it because callbacks are from another thread. 
    // Otherwise this will read the same input which is meant for callback input.
    
    pthread_mutex_init(&stdin_read_mutex, NULL);
    int fd = open("/dev/stdin", O_NONBLOCK);
    bool running = true;

    while(running) {

        // Get some user input char.
        pthread_mutex_lock(&stdin_read_mutex);
        char input_ch = 0;
        read(fd, &input_ch, 1); 
        pthread_mutex_unlock(&stdin_read_mutex);

        if(input_ch == 'q') {
            break;
        }
        if(input_ch == 'r') {
            const char* message = "Hello! Cryptography is interesting.";
            mutka_send_message(client, message, strlen(message));
        }

        // Check if we should disconnect.
        pthread_mutex_lock(&client->mutex);
        if((client->flags & MUTKA_CLFLG_SHOULD_DISCONNECT)) {
            printf("[libmutka]: Client should disconnect.\n");
            running = false;
        }
        pthread_mutex_unlock(&client->mutex);
        mutka_sleep_ms(100);
    }

    close(fd);

    mutka_disconnect(client);
    printf("disconnected from %s\n", __FILE__);
    return 0;
}



