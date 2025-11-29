#ifndef LIBMUTKA_PACKET_H
#define LIBMUTKA_PACKET_H

#include <stdbool.h>
#include <stddef.h>

#include "string.h"
#include "cryptography.h"

#define MUTKA_RAW_PACKET_DEFMEMSIZE (1024 * 48)


// Encoding options
#define RPACKET_ENCODE_NONE    0x01
#define RPACKET_ENCODE         0x02

// This is used to append back of encrypted packets
// it is an identifier for the packet parser to know
// if its content is encrypted or not.
// Doesnt really matter alot what it is but as
// long as it doent have 0 bytes.
#define MUTKA_ENCRYPTED_PACKET_TAIL 0x30FFFFFFEEEEEEEE
#define MUTKA_ENCRYPTED_PACKET_TAIL_NBYTES 8




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
    
    
    // If 'element[n].data' is encoded, 
    // it cannot be decoded straight back to 'data' itself.
    struct mutka_str tmp_decode_str;
};


// "STOC" prefix means Server To Client.
// "CTOS" prefix means Client To Server.
// "SPV"  prefix means it works for both sides
//        and its short for "Skip Packet Verification".
//        "spv" packets do not have defined structure to them.
//        Usually used for very simple data without encryption.
//
// NOTE:  Not all STOC/CTOS packets have defined structure.
enum mutka_packet_ids : int {

    // MUTKA_SERVER_ENABLE_CAPTCHA must be set for this to be used.
    // After the metadata keys have been exchanged
    // and client is not yet verified
    // It will send this packet containing the captcha buffer to client.
    // If the answer is correct and server doesnt have password enabled
    // the client is verified after good response.
    SPV_MPACKET_CAPTCHA,

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
    STOC_MPACKET_HOST_PUBLKEY,

    // Client and server will exchange metadata keys
    // for encrypting and decrypting packet metadata.
    // The packet's metadata doesnt contain sensetive information
    // but it does add layer of privacy.
    //
    // The handshake can be initiated by the client
    // by sending this packet id with randomly generated "client_nonce".
    // The server will generate a ML-DSA-87 signature which the client
    // will try to verify with same "client_nonce" parameter as it sent.
    CTOS_MPACKET_EXCH_METADATA_KEYS,
    STOC_MPACKET_EXCH_METADATA_KEYS,

    // Client must respond to metadata key exchange
    // if it was succesfully completed
    // server will send 'STOC_MPACKET_SERVER_INFO'
    CTOS_MPACKET_INITIAL_SEQ_COMPLETE,

    // The server will respond with general info to client
    // when metadata key exchange is complete.
    STOC_MPACKET_SERVER_INFO,
    
    // Clients must inform the server about their
    // public message keys and public identity key.
    // This is done because the server
    // must know message receiver's public keys
    // for message sender to encrypt the message correctly for the receiver.
    CTOS_MPACKET_DEPOSIT_PUBLIC_MSGKEYS,

    // When client sends this packet to server.
    // the server may respond with
    // other client's public keys and random unique identifier
    // required for the sender to encrypt messages for each receiver.
    CTOS_MPACKET_ASK_PEER_PUBLKEYS,
    STOC_MPACKET_PEER_PUBLKEYS,

    // After client has got all other client's public keys.
    // Server sends this packet to inform there is no more at the moment.
    STOC_MPACKET_ALL_PEER_PUBLKEYS_SENT,

    // Client can send encrypted messages with this packet
    // after they received all peers public message keys.
    CTOS_MPACKET_SEND_MSG_CIPHER,

    // Server sends this packet when it received MPACKET_SEND_MSG
    STOC_MPACKET_SERVER_MSG_ACK,

    // Clients can receive their encrypted 
    // messages with this packet id.
    STOC_MPACKET_NEW_MSG_CIPHER,




    MUTKA_NUM_PACKETS
};


// The received data could be used directly from
// 'struct mutka_packet' but this kind of approach
// will "force" to validate the data before it is ever used.
struct mpacket_data {
    int packet_id;
    union {

        struct STOC_PEER_PUBLKEYS_struct
        {
            int                  peer_uid;
            key_mldsa87_publ_t   identity_publkey;
            key_mlkem1024_publ_t mlkem_publkey;
            key128bit_t          x25519_publkey;
            signature_mldsa87_t  signature;
        }
        STOC_PEER_PUBLKEYS;
        
        // ------------------------------------------

        struct STOC_HOST_PUBLKEY_struct
        {
            key_mldsa87_publ_t host_publkey;
        }
        STOC_HOST_PUBLKEY;

        // ------------------------------------------

        struct STOC_EXCH_METADATA_KEYS_struct
        {
            key128bit_t             peer_x25519_publkey;
            key_mlkem1024_cipher_t  peer_mlkem_cipher;
            signature_mldsa87_t     signature;
            uint8_t                 hkdf_salt [HKDF_SALT_LEN];
        }
        STOC_EXCH_METADATA_KEYS;

        // ------------------------------------------

        struct CTOS_EXCH_METADATA_KEYS_struct
        {
            key128bit_t             peer_x25519_publkey;
            key_mlkem1024_publ_t    peer_mlkem_publkey;
        }
        CTOS_EXCH_METADATA_KEYS;

        // ------------------------------------------

        struct CTOS_DEPOSIT_PUBLIC_MSGKEYS_struct
        {
            key_mldsa87_publ_t     identity_publkey;
            key128bit_t            x25519_publkey;
            key_mlkem1024_publ_t   mlkem_publkey;
            signature_mldsa87_t    signature;
        }
        CTOS_DEPOSIT_PUBLIC_MSGKEYS;

        // ------------------------------------------

        struct STOC_NEW_MSG_CIPHER_struct
        {
            int               receiver_uid;
            struct mutka_str* msg_cipher;
            struct mutka_str* gcm_aad;
            uint8_t           gcm_iv  [AESGCM_IV_LEN];
            uint8_t           gcm_tag [AESGCM_TAG_LEN];
            uint8_t           hkdf_salt [HKDF_SALT_LEN];
            
            key_mldsa87_publ_t      identity_publkey;
            key128bit_t             x25519_publkey;
            key_mlkem1024_cipher_t  mlkem_cipher;
            signature_mldsa87_t     signature;
        }
        STOC_NEW_MSG_CIPHER;
    
    };
};

const char* mutka_get_packet_name(int packet_id);


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

bool mutka_validate_parsed_packet(struct mpacket_data* packet_struct, struct mutka_packet* packet);
void mutka_free_validated_packet(struct mpacket_data* packet_data);



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

// Can be used for forwarding packets with different packet ids.
// After this function 'inpacket->raw_packet'(containing new_packet_id) can be sent.
void mutka_replace_inpacket_id
(
    struct mutka_packet* inpacket,
    int new_packet_id
);

// This function will encrypt packet data before its sent.
void mutka_send_encrypted_rpacket
(
    int socket_fd,
    struct mutka_raw_packet* packet,
    key128bit_t* mtdata_hshared_key
);

// IMPORTANT NOTE: 
// mutka_send_clear_rpacket() should
// only be used for initial sequence packets
// THIS FUNCTION DOES NOT ENCRYPT ANYTHING.
void mutka_send_clear_rpacket(int socket_fd, struct mutka_raw_packet* packet);


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
