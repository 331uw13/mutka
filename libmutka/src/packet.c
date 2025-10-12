#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "../include/packet.h"
#include "../include/mutka.h"


void mutka_alloc_rpacket(struct mutka_raw_packet* packet, size_t size){
    packet->data = malloc(size);
    packet->memsize = size;
}

void mutka_free_rpacket(struct mutka_raw_packet* packet) {
    if(packet->data) {
        free(packet->data);
        packet->data = NULL;
        packet->memsize = 0;
        packet->size = 0;
    }
}

void mutka_rpacket_prep(struct mutka_raw_packet* packet, int packet_id) {
    memset(packet->data, 0, (packet->size < packet->memsize) ? packet->size : packet->memsize);
    packet->size = 0;
    
    memmove(packet->data, &packet_id, sizeof(packet_id));
    packet->size += sizeof(packet_id);
    packet->has_write_error = false;
}


static bool mutka_packet_add_bytes(struct mutka_raw_packet* packet, const char* bytes, size_t size) {
    if((packet->size + size) >= packet->memsize) {
        return false;
    }
    memmove(&packet->data[packet->size], bytes, size);
    packet->size += size;
    
    return true;
}


bool mutka_rpacket_add_ent(struct mutka_raw_packet* packet, const char* label,
                          const char* data, size_t data_size) {

    if(packet->has_write_error) {
        return false;
    }

    // Format: packet_id entry:data|entry:data|entry:data ...

    if(!mutka_packet_add_bytes(packet, label, strlen(label))) { 
        packet->has_write_error = true;
        return false;
    }
    if(!mutka_packet_add_bytes(packet, ":", 1)) { 
        packet->has_write_error = true;
        return false;
    }
    if(!mutka_packet_add_bytes(packet, data, data_size)) { 
        packet->has_write_error = true;
        return false;
    }
    if(!mutka_packet_add_bytes(packet, "|", 1)) { 
        packet->has_write_error = true;
        return false;
    }

    return true;
}

void mutka_send_rpacket(int socket_fd, struct mutka_raw_packet* packet) {
    if(packet->has_write_error) {
        return;
    }

    send(socket_fd, packet->data, packet->size, 0);
}


void mutka_free_packet(struct mutka_packet* packet) {
    if(!packet->elements) {
        return;
    }

    for(size_t i = 0; i < packet->num_elements; i++) {
        struct mutka_packet_elem* elem = &packet->elements[i];
        mutka_str_free(&elem->label);
        mutka_str_free(&elem->data);
    }

    free(packet->elements);
    packet->elements = NULL;
}



#define MUTKA_PACKET_MADD_ELEMS 16

static bool mutka_packet_memcheck(struct mutka_packet* packet) {
    if(!packet->elements) {
        packet->elements = malloc(MUTKA_PACKET_MADD_ELEMS * sizeof *packet->elements);
        packet->num_elems_allocated = MUTKA_PACKET_MADD_ELEMS;
        // TODO: handle memory errors.
        return true;
    }

    if(packet->num_elements+1 < packet->num_elems_allocated) {
        return true;
    }

    packet->num_elems_allocated += MUTKA_PACKET_MADD_ELEMS;
    struct mutka_packet_elem* new_ptr = realloc(packet->elements, packet->num_elems_allocated);
    if(!new_ptr) {
        // TODO: handle memory errors.
        return false;
    }

    packet->elements = new_ptr;

    return true;
}

void mutka_clear_packet(struct mutka_packet* packet) {
    if(!packet->elements) {
        return;
    }    

    for(uint32_t i = 0; i < packet->num_elements; i++) {
        struct mutka_packet_elem* elem = &packet->elements[i];
        mutka_str_clear(&elem->label);
        mutka_str_clear(&elem->data);
    }

    packet->num_elements = 0;
    packet->id = -1;
}


bool mutka_parse_rpacket(struct mutka_packet* packet, struct mutka_raw_packet* raw_packet) {
    if(raw_packet->size < sizeof(packet->id)) {
        mutka_set_errmsg("Packet doesnt have any useful data.");
        return false;
    }

    mutka_clear_packet(packet);

    // Format: packet_id entry:data|entry:data|entry:data ...
    
    memmove(&packet->id, raw_packet->data, sizeof(packet->id));
    if(packet->id >= MUTKA_NUM_PACKETS) {
        mutka_set_errmsg("Packet has invalid ID or it was not set.");
        return false;
    }

    if(!mutka_packet_memcheck(packet)) {
        return false;
    }

    struct mutka_packet_elem* curr_elem = &packet->elements[0];

    char* ch = raw_packet->data + sizeof(packet->id);
    char* lastch = raw_packet->data + raw_packet->size;

    while(ch < lastch) {
            
        // Read element label:
        while(ch < lastch) {
            if(*ch == ':') { // Label and data separator.
                ch++;
                break;
            }
        
            mutka_str_pushbyte(&curr_elem->label, *ch);
            ch++;
        }

        // Read element data:
        while(ch < lastch) {
            if(*ch == '|') { // Element separator.
                if(!mutka_packet_memcheck(packet)) {
                    return false;
                }
                packet->num_elements++;
                curr_elem = &packet->elements[packet->num_elements];
                ch++;
                break;
            }

            mutka_str_pushbyte(&curr_elem->data, *ch);
            ch++;
        }
        
    }

    return true;
}

#include <stdio.h>

int mutka_recv_incoming_packet(struct mutka_packet* packet, int socket_fd) {
    if(!mutka_socket_rdready_inms(socket_fd, 0)) {
        return M_NONEW_PACKET;
    }

    ssize_t recv_result = recv(
            socket_fd,
            packet->raw_packet.data,
            packet->raw_packet.memsize, MSG_DONTWAIT);

    if(recv_result <= 0) {
        return M_LOST_CONNECTION;
    }

    packet->raw_packet.size = recv_result;
    if(!mutka_parse_rpacket(packet, &packet->raw_packet)) {
        return M_PACKET_PARSE_ERR;
    }

    return M_NEW_PACKET_AVAIL;
}



