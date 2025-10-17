
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "../../../libmutka/include/mutka.h"
#include "../../../libmutka/include/cryptography.h"




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
        fprintf(stderr, "No nickname. Usage example: %s test-user-123\n", argv[0]);
        return 1;
    }
    char* nickname = argv[1];
    
    mutka_set_errmsg_callback(mutka_error);


    struct mutka_client_cfg config = 
    (struct mutka_client_cfg)
    {
        .host = "127.0.0.1",
        .port = 35580,
        .nickname = nickname,
        .mutka_cfgdir = NULL, // TODO: Accept null. 
    };


   
    if(!mutka_cfg_trustedkey_exists(&config)) {
        printf("\033[33mYour trusted-key was not found for nickname \"%s\"\n"
                "Would you like to generate it? (yes/no): \033[0m",
                nickname);
        fflush(stdout);

        char input[8] = { 0 };
        read(STDIN_FILENO, input, sizeof(input));
        if((input[0] != 'Y') && (input[0] != 'y')) {
            return 1;
        }

        if(mutka_cfg_generate_trustedkey(&config)) {
            printf("Your trusted-key is generated.\n"
                    "You should now add your peer trusted-key\n");
        }
        
        return 0;
    }

    struct mutka_client* client = mutka_connect(&config);
    if(!client) {
        return 1;
    }

    client->packet_received_callback = packet_received;


    printf("press enter to disconnect\n");
    char tmp = 0;
    read(1, &tmp, 1);

    mutka_disconnect(client);
    return 0;
}




