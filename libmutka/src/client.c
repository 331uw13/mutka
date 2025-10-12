#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#include "../include/client.h"
#include "../include/mutka.h"



struct mutka_client* mutka_connect(const char* host, uint16_t port) {
    struct mutka_client* client = malloc(sizeof *client);
    
    client->socket_fd = -1;
    client->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(client->socket_fd < 0) {
        mutka_set_errmsg("Failed to open socket. %s", strerror(errno));
        free(client);
        client = NULL;
        goto out;
    }

    client->socket_addr.sin_family = AF_INET;
    client->socket_addr.sin_port = htons(port);

    inet_pton(AF_INET, host, &client->socket_addr.sin_addr);


    int connect_result = connect(
            client->socket_fd,
            (struct sockaddr*)&client->socket_addr,
            sizeof(client->socket_addr));

    if(connect_result != 0) {
        mutka_set_errmsg("Connection failed to (%s:%i) | %s", host, port, strerror(errno));
        close(client->socket_fd);
        free(client);
        client = NULL;
        goto out;
    }

    mutka_alloc_rpacket(&client->out_raw_packet, MUTKA_RAW_PACKET_DEFMEMSIZE);
    mutka_alloc_rpacket(&client->inpacket.raw_packet, MUTKA_RAW_PACKET_DEFMEMSIZE);

out:
    return client;
}


void mutka_disconnect(struct mutka_client* client) {
    if(!client) {
        return;
    }

    if(client->socket_fd >= 0) {
        close(client->socket_fd);
        client->socket_fd = -1;
    }

    mutka_free_rpacket(&client->out_raw_packet);
    free(client);
}


