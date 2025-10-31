#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>

#include <stdio.h>


#include "../include/packet.h"
#include "../include/mutka.h"

#define DEBUG




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


bool mutka_rpacket_add_ent
(
    struct mutka_raw_packet* packet,
    const char* label,
    char* data,
    size_t data_size,
    uint8_t encoding_option
){
    struct mutka_str data_encoded;
    data_encoded.bytes = NULL;

    if(packet->has_write_error) {
        return false;
    }


    if(encoding_option == RPACKET_ENCODE_BASE64) {
        mutka_str_alloc(&data_encoded);
        if(!mutka_openssl_BASE64_encode(&data_encoded, data, data_size)) {
            packet->has_write_error = true;
            goto out;
        }
    }


    // Format: ... label:<encoding_option>data| ...

    if(!mutka_packet_add_bytes(packet, label, strlen(label))) { 
        packet->has_write_error = true;
        goto out;
    }
    if(!mutka_packet_add_bytes(packet, ":", 1)) { 
        packet->has_write_error = true;
        goto out;
    }

    if(!mutka_packet_add_bytes(packet, (char*)&encoding_option, sizeof(encoding_option))) {
        packet->has_write_error = true;
        goto out;
    }
   
    if(encoding_option != RPACKET_ENCODE_NONE) {
        if(!mutka_packet_add_bytes(packet, data_encoded.bytes, data_encoded.size)) { 
            packet->has_write_error = true;
            goto out;
        }
    }
    else {
        if(!mutka_packet_add_bytes(packet, data, data_size)) { 
            packet->has_write_error = true;
            goto out;
        }
    }
    
    if(!mutka_packet_add_bytes(packet, "|", 1)) { 
        packet->has_write_error = true;
        goto out;
    }

out:
    if(data_encoded.bytes) {
        mutka_str_free(&data_encoded);
    }

    return !packet->has_write_error;
}



void mutka_send_rpacket(int socket_fd, struct mutka_raw_packet* packet) {
    if(packet->has_write_error) {
        return;
    }

    if(packet->size + sizeof(packet->size) >= packet->memsize) {
        mutka_set_errmsg("Packet is too large to be sent.");
        return;
    }

    packet->size += sizeof(packet->size);

    // Make room for expected packet size.
    memmove(packet->data + sizeof(packet->size), packet->data, packet->size);
        
    // Add packet size.
    memmove(packet->data, &packet->size, sizeof(packet->size));

#ifdef DEBUG
    printf("SENT PACKET:\n");
    for(uint32_t i = 0; i < packet->size; i++) {
        printf("%02X ", (uint8_t)packet->data[i]);
        if((i % 24) == 23) {
            printf("\n");
        }
    }
    printf("\n-------------------------------------------\n");
#endif


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

// Allocate more space for packet 'elements' if needed.
static bool mutka_packet_memcheck(struct mutka_packet* packet) { 
    if(!packet->elements) {
        packet->elements = malloc(MUTKA_PACKET_MADD_ELEMS * sizeof *packet->elements);
        if(!packet->elements) {
            // TODO: handle memory errors.
            return false;
        }

        packet->num_elems_allocated = MUTKA_PACKET_MADD_ELEMS;
        for(uint32_t i = 0; i < packet->num_elems_allocated; i++) {
            packet->elements[i].label.bytes = NULL;
            packet->elements[i].data.bytes = NULL;
        }
        return true;
    }

    if(packet->num_elements+1 < packet->num_elems_allocated) {
        return true;
    }

    const uint32_t prev_num_elems = packet->num_elems_allocated;

    packet->num_elems_allocated += MUTKA_PACKET_MADD_ELEMS;
    struct mutka_packet_elem* new_ptr = realloc(packet->elements, packet->num_elems_allocated);
    if(!new_ptr) {
        // TODO: handle memory errors.
        return false;
    }
    
    packet->elements = new_ptr;

    for(uint32_t i = prev_num_elems; i < packet->num_elems_allocated; i++) {
        packet->elements[i].label.bytes = NULL;
        packet->elements[i].data.bytes = NULL;
    }

    return true;
}

void mutka_clear_packet(struct mutka_packet* packet) {
    if(!packet->elements) {
        return;
    }    

    //printf("%s: %i\n", __func__, packet->num_elements);

    for(uint32_t i = 0; i < packet->num_elements; i++) {
        struct mutka_packet_elem* elem = &packet->elements[i];
        mutka_str_clear(&elem->label);
        mutka_str_clear(&elem->data);
    }

    packet->expected_size = 0;
    packet->num_elements = 0;
    packet->id = -1;
}


bool mutka_parse_rpacket(struct mutka_packet* packet, struct mutka_raw_packet* raw_packet) {
    if(raw_packet->size < sizeof(packet->id)) {
        mutka_set_errmsg("Packet doesnt have any useful data.");
        return false;
    }

#ifdef DEBUG

    printf("RECEIVED PACKET:\n");
    for(uint32_t i = 0; i < raw_packet->size; i++) {
        printf("%02X ", (uint8_t)raw_packet->data[i]);
        if((i % 24) == 23) {
            printf("\n");
        }
    }

    printf("\n-------------------------------------------\n");

#endif
    // Format: packet_size, packet_id, entry:data|entry:data|entry:data ...


    mutka_clear_packet(packet);
  
    size_t header_size = 0;

    memmove(&packet->expected_size, &raw_packet->data[header_size], sizeof(packet->expected_size));
    header_size += sizeof(packet->expected_size);
    
    memmove(&packet->id, &raw_packet->data[header_size], sizeof(packet->id));
    header_size += sizeof(packet->id);

    if(packet->id >= MUTKA_NUM_PACKETS) {
        mutka_set_errmsg("Packet has invalid ID or it was not set.");
        return false;
    }
    

    printf("EXPECTED = %i, RECV = %i\n", packet->expected_size, raw_packet->size);

    if(!mutka_packet_memcheck(packet)) {
        return false;
    }

    struct mutka_packet_elem* curr_elem = &packet->elements[0];

    char* ch = raw_packet->data + header_size;
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
        mutka_str_pushbyte(&curr_elem->label, 0);

        if(ch >= lastch) {
            return false;
        }

        // Read data encoding option.
        curr_elem->encoding = (uint8_t)*ch;
        ch++;

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
        if(curr_elem->encoding == RPACKET_ENCODE_NONE) {
            mutka_str_pushbyte(&curr_elem->data, 0);
        }
        
    }

    printf("PACKET PARSED OK!\n");
    return true;
}


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



