#ifndef LIBMUTKA_PACKET_H
#define LIBMUTKA_PACKET_H

#include <stdbool.h>
#include <stddef.h>

#include "string.h"

#define MUTKA_RAW_PACKET_DEFMEMSIZE (1024 * 8) 



struct mutka_raw_packet {
    char*     data;
    uint32_t  size;
    uint32_t  memsize;
    bool      has_write_error;
};



struct mutka_packet_elem {
    struct mutka_str label;
    struct mutka_str data;
};

// Raw packet can be parsed into its elements when it is received.
struct mutka_packet {
    
    int                       id;
    struct mutka_packet_elem* elements;
    uint32_t                  num_elements;
    uint32_t                  num_elems_allocated;
    
    struct mutka_raw_packet   raw_packet;

};


enum mutka_packet_ids : int {
    
    // When client connects to the server,
    // They will exchange X25519 public keys
    // for encrypting and decrypting the packet metadata.
    MPACKET_HANDSHAKE,


    MUTKA_NUM_PACKETS
};

void mutka_alloc_rpacket(struct mutka_raw_packet* packet, size_t size);
void mutka_free_rpacket(struct mutka_raw_packet* packet);

void mutka_free_packet(struct mutka_packet* packet);

// Clears previous packet data and writes packet_id.
void mutka_rpacket_prep(struct mutka_raw_packet* packet, int packet_id);

// NOTE: 'label' must be NULL terminated.
bool mutka_rpacket_add_ent(struct mutka_raw_packet* packet, const char* label,
                          const char* data, size_t data_size);

void mutka_send_rpacket(int socket_fd, struct mutka_raw_packet* packet);

// Automatically allocates more memory for 'mutka_packet->elements'
// if needed. Returns 'true' on success. 
// On failure 'false' is returned and error can be read with 'mutka_get_errmsg'
bool mutka_parse_rpacket(struct mutka_packet* packet, struct mutka_raw_packet* raw_packet);

void mutka_clear_packet(struct mutka_packet* packet);

// On success it parses raw packet elements into 'packet' and returns the packet size.
// When no packet is to be read 0 is returned.
// If it fails -1 is returned. 
int mutka_recv_incoming_packet(struct mutka_packet* packet, int socket_fd);



#endif
