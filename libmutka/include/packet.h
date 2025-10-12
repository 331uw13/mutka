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

    // When client connects to server,
    // They will initiate a handshake.
    // Here the server will also generate new packet metadata keypair
    MPACKET_HELLO,

    // Server will respond to MPACKET_HELLO with this packet
    // containing the X25519 packet metadata public key for the specific client.
    // The metadata keys are used to encrypt packet metadata.
    // NOTE: packet metadata does _not_ contain any "secret" data
    // and is not a problem if someone gets hold of it, but this adds a layer of privacy.
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


#define M_NONEW_PACKET 1
#define M_NEW_PACKET_AVAIL 2
#define M_LOST_CONNECTION 3
#define M_PACKET_PARSE_ERR 4

// This function is non blocking and will return following: 
// M_NONEW_PACKET, M_NEW_PACKET_AVAIL, M_LOST_CONNECTION or M_PACKET_PARSE_ERR.
//
// if M_PACKET_PARSE_ERR is returned the error message can be read with mutka_get_errmsg()
int mutka_recv_incoming_packet(struct mutka_packet* packet, int socket_fd);



#endif
