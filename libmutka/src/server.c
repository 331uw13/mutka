#include <stdlib.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "../include/server.h"
#include "../include/mutka.h"


static struct server_global {
    pthread_t acceptor_thread;
    pthread_t recv_thread;
}
global;


void* mutka_server_acceptor_thread_func(void* arg);
void* mutka_server_recvdata_thread_func(void* arg);
void mutka_server_handle_packet(struct mutka_server* server, struct mutka_client* client);

struct mutka_server* mutka_create_server(struct mutka_server_cfg config) { 
    struct mutka_server* server = malloc(sizeof *server);
    
    server->config = config;

    server->socket_fd = -1;
    server->socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(server->socket_fd < 0) {
        mutka_set_errmsg("Failed to open socket for server | %s", strerror(errno));
        free(server);
        server = NULL;
        goto out;
    }

    explicit_bzero(&server->socket_addr, sizeof(server->socket_addr));

    server->socket_addr.sin_family = AF_INET;
    server->socket_addr.sin_addr.s_addr = htonl(INADDR_ANY); // TODO: Allow host to be configured.
    server->socket_addr.sin_port = htons(config.port);

    if((config.flags & MUTKA_S_FLG_REUSEADDR)) {
        socklen_t opt = 1;
        setsockopt(server->socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    }

    int bind_result = bind(
            server->socket_fd,
            (struct sockaddr*)&server->socket_addr,
            sizeof(server->socket_addr));

    if(bind_result != 0) {
        mutka_set_errmsg("Failed bind address to socket | %s", strerror(errno));
        close(server->socket_fd);
        free(server);
        server = NULL;
        goto out;
    }


    const int listen_queue_hint = 6;
    int listen_result = listen(server->socket_fd, listen_queue_hint);

    if(listen_result != 0) {
        mutka_set_errmsg("Failed set socket into listen mode | %s", strerror(errno));
        close(server->socket_fd);
        free(server);
        server = NULL;
        goto out;
    }

    server->inpacket.elements = NULL;
    mutka_alloc_rpacket(&server->out_raw_packet, MUTKA_RAW_PACKET_DEFMEMSIZE);
    mutka_alloc_rpacket(&server->inpacket.raw_packet, MUTKA_RAW_PACKET_DEFMEMSIZE);

    server->clients = malloc(config.max_clients * sizeof *server->clients);
    server->num_clients = 0;

    pthread_mutex_init(&server->mutex, NULL);

    pthread_create(&global.acceptor_thread, NULL, mutka_server_acceptor_thread_func, server);
    pthread_create(&global.recv_thread,     NULL, mutka_server_recvdata_thread_func, server);


out:
    return server;
}


void mutka_close_server(struct mutka_server* server) {
    if(!server) {
        return;
    }

    pthread_cancel(global.acceptor_thread);
    pthread_cancel(global.recv_thread);

    pthread_join(global.acceptor_thread, NULL);
    pthread_join(global.recv_thread, NULL);

    for(uint32_t i = 0; i < server->num_clients; i++) {
        struct mutka_client* client = &server->clients[i];
        if(client->socket_fd >= 0) {
            close(client->socket_fd);
            client->socket_fd = -1;
        }
    }

    mutka_free_rpacket(&server->out_raw_packet);
    mutka_free_rpacket(&server->inpacket.raw_packet);

    mutka_free_packet(&server->inpacket);

    close(server->socket_fd);
    free(server);
}

void* mutka_server_acceptor_thread_func(void* arg) {
    struct mutka_server* server = (struct mutka_server*)arg;
    while(1) {

        pthread_mutex_lock(&server->mutex);
        if(server->num_clients+1 >= server->config.max_clients) {
            pthread_mutex_unlock(&server->mutex);

            mutka_sleep_ms(500);
            continue;
        }

        pthread_mutex_unlock(&server->mutex);


        struct mutka_client client;
        socklen_t socket_len = sizeof(client.socket_addr);
        client.socket_fd = accept(server->socket_fd, (struct sockaddr*)&client.socket_addr, &socket_len);

        if(client.socket_fd < 0) {
            // TODO
            continue;
        }

        pthread_mutex_lock(&server->mutex);
        
        struct mutka_client* new_client_ptr = &server->clients[server->num_clients];
        *new_client_ptr = client;
        server->num_clients++;
        server->config.client_connected_callback(server, new_client_ptr);

        pthread_mutex_unlock(&server->mutex);
    }
    return NULL;
}

#include <stdio.h>

void* mutka_server_recvdata_thread_func(void* arg) {
    struct mutka_server* server = (struct mutka_server*)arg;

    while(1) {
        pthread_mutex_lock(&server->mutex);

        for(size_t i = 0; i < server->num_clients; i++) {
            struct mutka_client* client = &server->clients[i];
           
            int rd = mutka_recv_incoming_packet(&server->inpacket, client->socket_fd);
            if(rd > 0) {
                mutka_server_handle_packet(server, client);
            }
        }

        pthread_mutex_unlock(&server->mutex);
        mutka_sleep_ms(100);
    }
    return NULL;
}

void mutka_server_handle_packet(struct mutka_server* server, struct mutka_client* client) {

    // TODO: Do internal packet handling.

    server->config.packet_received_callback(server, client);
}


