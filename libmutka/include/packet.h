#ifndef LIBMUTKA_PACKET_H
#define LIBMUTKA_PACKET_H

#include <stdbool.h>
#include <stddef.h>

#include "string.h"
#include "key.h"

#define MUTKA_RAW_PACKET_DEFMEMSIZE (1024 * 8) 


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

    MPACKET_HOST_PUBLIC_KEY,

    // Client and server will exchange metadata keys
    // for encrypting and decrypting packet metadata.
    // The packet's metadata doesnt contain sensetive information
    // but it does add layer of privacy.
    //
    // The handshake can be initiated by the client
    // by sending this packet id with randomly generated "client_nonce"
    // The server will generate a signature which the client
    // will try to verify with same "client_nonce" parameter as it sent.
    // That will reduce the risk of MITM attacks, because if the attacker
    // tries to generate its own keys and signature, the client will not be able to
    // verify the signature. Clients will have server's ed25519 public key stored on disk.
    // Also clients receive a warning 
    // if the server's ed25519 public key ever changes.
    // 
    // NOTE: First contact MITM attacks cannot to be detected this way
    //       but it will provide protection for future. 
    MPACKET_EXCHANGE_METADATA_KEYS,

    // Client must respond to metadata key exchange
    MPACKET_HOST_SIGNATURE_OK,
    MPACKET_HOST_SIGNATURE_FAILED,

    // MUTKA_SERVER_ENABLE_CAPTCHA must be set for this to be used.
    // After the metadata keys have been exchanged
    // and client is not yet verified
    // It will send this packet containing the captcha buffer to client.
    // If the answer is correct and server doesnt have password enabled
    // the client is verified after good response.
    MPACKET_CAPTCHA,


    //MPACKET_GET_CLIENTS_X25519_PUBLKEYS,



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
void mutka_send_rpacket
(
    int socket_fd,
    struct mutka_raw_packet* packet,
    key128bit_t* self_metadata_privkey,
    key128bit_t* peer_metadata_publkey
);

// IMPORTANT NOTE: 
// mutka_send_clear_rpacket() should only be used for initial packets (metadata key exchange)
// THIS FUNCTION DOES NOT ENCRYPT ANYTHING.
void mutka_send_clear_rpacket(int socket_fd, struct mutka_raw_packet* packet);


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
