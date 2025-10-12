#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#include "../include/client.h"
#include "../include/mutka.h"



static struct client_global {
    
    pthread_t recv_thread;

}
global;


void* mutka_client_recv_thread(void* arg);
void mutka_client_handle_packet(struct mutka_client* client);


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

    pthread_create(&global.recv_thread, NULL, mutka_client_recv_thread, client);


    // Initiate handshake.
    mutka_rpacket_prep(&client->out_raw_packet, MPACKET_HELLO);
    mutka_send_rpacket(client->socket_fd, &client->out_raw_packet);


out:
    return client;
}

void mutka_free_client(struct mutka_client* client) {
    if(client->socket_fd >= 0) {
        close(client->socket_fd);
        client->socket_fd = -1;
    }

    mutka_free_keypair(&client->metadata_keys);
    mutka_str_free(&client->peer_metadata_publkey);
}

void mutka_disconnect(struct mutka_client* client) {
    if(!client) {
        return;
    }

    pthread_cancel(global.recv_thread);
    pthread_join(global.recv_thread, NULL);

    mutka_free_client(client);

    mutka_free_rpacket(&client->out_raw_packet);
    free(client);
}


void* mutka_client_recv_thread(void* arg) {
    struct mutka_client* client = (struct mutka_client*)arg;
    while(true) {
        pthread_mutex_lock(&client->mutex);

        int rd = mutka_recv_incoming_packet(&client->inpacket, client->socket_fd);
        if(rd > 0) {
            mutka_client_handle_packet(client);
        }

        pthread_mutex_unlock(&client->mutex);
        mutka_sleep_ms(100);
    }
    return NULL;
}

#include <stdio.h> 
void mutka_client_handle_packet(struct mutka_client* client) {
    // NOTE: client->mutex is locked here.

    // Check for internal packets.
    switch(client->inpacket.id) {
        case MPACKET_HANDSHAKE:
            printf("%s:%s\n", client->inpacket.elements[0].label.bytes, client->inpacket.elements[0].data.bytes);

            return;

    }

    client->packet_received_callback(client);
}


