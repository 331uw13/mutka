
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "../../../libmutka/include/mutka.h"



void client_connected(struct mutka_server* server, struct mutka_client* client) {

    printf("client connected. (socket_fd = %i)\n", client->socket_fd);

}

void client_disconnected(struct mutka_server* server, struct mutka_client* client) {
    
    printf("client disconnected. (socket_fd = %i)\n", client->socket_fd);
}


void packet_received(struct mutka_server* server, struct mutka_client* client) {
    
    printf("packet received. (id = %i)\n", server->inpacket.id);

}



int main() {

    struct mutka_server_cfg config = (struct mutka_server_cfg) {
        .port = 35580,
        .max_clients = 8,
        .flags = (MUTKA_S_FLG_REUSEADDR),

        // Callbacks
        .client_connected_callback    = client_connected,
        .client_disconnected_callback = client_disconnected,
        .packet_received_callback     = packet_received
    };

    struct mutka_server* server = mutka_create_server(config);
    if(!server) {
        fprintf(stderr, "ERROR: %s\n", mutka_get_errmsg());
    }


    printf("press enter to shutdown the server.\n");
    char tmpbuf[1] = { 0 };
    read(1, tmpbuf, 1);


    mutka_close_server(server);
    printf("server closed\n");
    return 0;
}




