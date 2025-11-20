
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define MUTKA_SERVER
#include "../../../libmutka/include/mutka.h"


void mutka_error(char* buffer, size_t size) {
    (void)size;
    printf("[libmutka error]: %s\n", buffer);
}



void client_connected(struct mutka_server* server, struct mutka_client* client) {
    printf("client connected. (uid = %i) (socket_fd = %i)\n", client->uid, client->socket_fd);
}

void client_disconnected(struct mutka_server* server, struct mutka_client* client) {
    printf("client disconnected. (uid = %i) (socket_fd = %i)\n", client->uid, client->socket_fd);
}


void packet_received(struct mutka_server* server, struct mutka_client* client) {
    printf("packet received. (id = %i)\n", server->inpacket.id);
}


bool accept_new_hostkeys() {
    printf("\033[33mGenerate new server keys? (yes/no): \033[0m");
    fflush(stdout);

    char input[6] = { 0 };
    read(STDIN_FILENO, input, sizeof(input));
    
    return ((input[0] == 'Y') || (input[0] == 'y'));
}


int main() {

    struct mutka_server_cfg config = (struct mutka_server_cfg) {
        .port = 35580,
        .max_clients = 8,
        .max_captcha_retries = 3,
        .flags = (MUTKA_SERVER_REUSEADDR/* | MUTKA_SERVER_CAPTCHA_ENABLED*/),
        
        .accept_new_hostkeys_callback   = accept_new_hostkeys,
        .client_connected_callback      = client_connected,
        .client_disconnected_callback   = client_disconnected,
        .packet_received_callback       = packet_received
    };
    
    mutka_set_errmsg_callback(mutka_error);

    printf("sizeof(struct mutka_server) = %li\n", sizeof(struct mutka_server));
    printf("sizeof(struct mutka_client) = %li\n", sizeof(struct mutka_client));


    struct mutka_server* server = mutka_create_server(config, "./host_keys");

    if(!server) {
        return 1;
    }


    printf("press enter to shutdown the server.\n");
    char tmpbuf[1] = { 0 };
    read(1, tmpbuf, 1);


    mutka_close_server(server);
    printf("server closed\n");
    return 0;
}




