#ifndef LIBMUTKA_PACKET_H
#define LIBMUTKA_PACKET_H

#include <stdbool.h>
#include <stddef.h>

#include "string.h"
#include "key.h"

#define MUTKA_RAW_PACKET_DEFMEMSIZE (1024 * 24) 


// Encoding options
#define RPACKET_ENCODE_NONE    0x01
#define RPACKET_ENCODE         0x02


struct mutka_raw_packet {
    char*     data;
    uint32_t  size;
    uint32_t  memsize;
    bool      has_write_error;
};

struct mutka_packet_elem {
    struct mutka_str label;
    struct mutka_str data;
    uint8_t          encoding;
};

// Received raw_packet can be parsed into its elements when it is received.
struct mutka_packet { 
    uint32_t                  expected_size;

    int                       id;
    struct mutka_packet_elem* elements;
    size_t                    num_elements;
    size_t                    num_elems_allocated;
    
    struct mutka_raw_packet   raw_packet; // Received raw packet
};


enum mutka_packet_ids : int {

    // If received packet expected_size doesnt match received size.
    // This packet will be sent.
    // TODO: MPACKET_RESEND,


    // When the client connects to server
    // the server will send its longterm ML-DSA-87 public key
    //
    // If the client has the host's public key saved on disk 
    // it will try and match it to existing one, 
    // but if it doesnt match a serious warning should be shown
    // (see "client.h" 'accept_host_public_key_change_callback()').
    //
    // If the host's public key doesnt exist on client's "trusted_hosts" file
    // 'accept_new_trusted_host_callback()' is called.
    MPACKET_HOST_PUBLIC_KEY,

    // Client and server will exchange metadata keys
    // for encrypting and decrypting packet metadata.
    // The packet's metadata doesnt contain sensetive information
    // but it does add layer of privacy.
    //
    // The handshake can be initiated by the client
    // by sending this packet id with randomly generated "client_nonce".
    // The server will generate a ML-DSA-87 signature which the client
    // will try to verify with same "client_nonce" parameter as it sent.
    MPACKET_EXCHANGE_METADATA_KEYS,

    // Client must respond to metadata key exchange
    // if it was succesfully completed.
    MPACKET_METADATA_KEY_EXHCANGE_COMPLETE,


    // MUTKA_SERVER_ENABLE_CAPTCHA must be set for this to be used.
    // After the metadata keys have been exchanged
    // and client is not yet verified
    // It will send this packet containing the captcha buffer to client.
    // If the answer is correct and server doesnt have password enabled
    // the client is verified after good response.
    MPACKET_CAPTCHA,



    MUTKA_NUM_PACKETS
};

void mutka_alloc_rpacket(struct mutka_raw_packet* packet, size_t size);
void mutka_free_rpacket(struct mutka_raw_packet* packet);

void mutka_inpacket_init(struct mutka_packet* inpacket);
void mutka_free_packet(struct mutka_packet* packet);

// Clears previous packet data and writes packet_id.
void mutka_rpacket_prep(struct mutka_raw_packet* packet, int packet_id);

// NOTE: 'label' must be NULL terminated.
bool mutka_rpacket_add_ent
(
    struct mutka_raw_packet* packet,
    const char* label,
    void*  data,
    size_t data_size,
    uint8_t encoding_option
);


// This function will encrypt packet data before its sent.
void mutka_send_encrypted_rpacket
(
    int socket_fd,
    struct mutka_raw_packet* packet,
    key128bit_t* metadata_shared_key
);

// IMPORTANT NOTE: 
// mutka_send_clear_rpacket() should only be used for initial packets (metadata key exchange)
// THIS FUNCTION DOES NOT ENCRYPT ANYTHING.
void mutka_send_clear_rpacket(int socket_fd, struct mutka_raw_packet* packet);

// Parse 'raw_packet' into packet's elements.
// Automatically allocates more memory for 'mutka_packet->elements' if needed.
// Returns 'true' on success. 
// On failure 'false' is returned and error can be read with 'mutka_get_errmsg'
bool mutka_parse_rpacket(struct mutka_packet* packet, struct mutka_raw_packet* raw_packet);

// Decrypts 'raw_packet' and calls 'mutka_parse_rpacket' if succesful.
bool mutka_parse_encrypted_rpacket
(
    struct mutka_packet* packet,
    struct mutka_raw_packet* raw_packet,
    key128bit_t* metadata_shared_key
);

void mutka_clear_packet(struct mutka_packet* packet);


#define M_NONEW_PACKET 1
#define M_NEW_PACKET_AVAIL 2
#define M_ENCRYPTED_RPACKET 3
#define M_LOST_CONNECTION 4
#define M_PACKET_PARSE_ERR 5

// This function is non blocking and will return one of above options.
// if M_PACKET_PARSE_ERR is returned the error message can be read with mutka_get_errmsg()
int mutka_recv_incoming_packet(struct mutka_packet* packet, int socket_fd);



#endif
