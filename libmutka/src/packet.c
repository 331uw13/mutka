#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <openssl/rand.h>

#include <stdio.h>


#include "../include/packet.h"
#include "../include/mutka.h"
#include "../include/memory.h"
#include "../include/cryptography.h"


#define RPACKET_HEADER_SIZE (sizeof(int)*2)

#define DEBUG
#define DEBUG_HEAD_N 100

#ifdef DEBUG
static void p_dump_packet(struct mutka_raw_packet* packet, const char* label) {
    printf("\033[90m===[ %s ]=======\033[0m\n", label);
    int column_count = 0;

    int byte_count = 0;
    char* ch = &packet->data[0];
    while(ch < packet->data + packet->size) {

        printf("%02X ", (uint8_t)*ch);

        column_count++;
        if(column_count > 32) {
            printf("\n");
            column_count = 0;
        }
        ch++;
        byte_count++;
        if(byte_count > DEBUG_HEAD_N) {
            printf("...\n");
            column_count = 0;
            break;
        }
    }
    if(column_count > 0) {
        printf("\n");
    }
    printf("\033[90m`-> %i bytes ---------\033[0m\n", packet->size);
}
#endif




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

void mutka_inpacket_init(struct mutka_packet* inpacket) {
    inpacket->expected_size = 0;
    inpacket->id = 0;
    inpacket->elements = NULL;
    inpacket->num_elements = 0;
    inpacket->num_elems_allocated = 0;
    mutka_str_alloc(&inpacket->tmp_decode_str);
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

    mutka_str_free(&packet->tmp_decode_str);
    free(packet->elements);
    packet->elements = NULL;
}

static bool p_mutka_packet_add_bytes(struct mutka_raw_packet* packet, const char* bytes, size_t size) {
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
    void* data,
    size_t data_size,
    uint8_t encoding_option
){
    struct mutka_str data_encoded;
    data_encoded.bytes = NULL;

    if(packet->has_write_error) {
        return false;
    }


    printf("%s: Add entry (data = %p, data_size = %li)\n",
            __func__, data, data_size);

    if(encoding_option == RPACKET_ENCODE) {
        mutka_str_alloc(&data_encoded);
        mutka_encode(&data_encoded, data, data_size);
    }


    // Format: ... <label>:<encoding_option><data>| ...

    if(!p_mutka_packet_add_bytes(packet, label, strlen(label))) { 
        packet->has_write_error = true;
        goto out;
    }
    if(!p_mutka_packet_add_bytes(packet, ":", 1)) { 
        packet->has_write_error = true;
        goto out;
    }

    if(!p_mutka_packet_add_bytes(packet, (char*)&encoding_option, sizeof(encoding_option))) {
        packet->has_write_error = true;
        goto out;
    }
   
    if(encoding_option != RPACKET_ENCODE_NONE) {
        if(!p_mutka_packet_add_bytes(packet, data_encoded.bytes, data_encoded.size)) { 
            packet->has_write_error = true;
            goto out;
        }
    }
    else {
        if(!p_mutka_packet_add_bytes(packet, data, data_size)) { 
            packet->has_write_error = true;
            goto out;
        }
    }
    
    if(!p_mutka_packet_add_bytes(packet, "|", 1)) { 
        packet->has_write_error = true;
        goto out;
    }

out:
    if(data_encoded.bytes) {
        mutka_str_free(&data_encoded);
    }

    return !packet->has_write_error;
}


static bool p_mutka_add_packet_expected_size(struct mutka_raw_packet* rpacket) {
    if(rpacket->has_write_error) {
        return false;
    }

    if(rpacket->size + sizeof(rpacket->size) >= rpacket->memsize) {
        mutka_set_errmsg("Packet is too large to be sent.");
        return false ;
    }

    rpacket->size += sizeof(rpacket->size);

    // Make room for expected packet size.
    memmove(rpacket->data + sizeof(rpacket->size), rpacket->data, rpacket->size);
        
    // Add packet size.
    memmove(rpacket->data, &rpacket->size, sizeof(rpacket->size));

    return true;
}


void mutka_send_clear_rpacket(int socket_fd, struct mutka_raw_packet* packet) {
    if(packet->has_write_error) {
        return;
    }

    if(!p_mutka_add_packet_expected_size(packet)) {
        return;
    }

#ifdef DEBUG
    p_dump_packet(packet, "Sent (Not Encrypted)");
#endif
    send(socket_fd, packet->data, packet->size, 0);
}



#define MEMCHECK_NOACTNEEDED 0
#define MEMCHECK_BUFRESIZED 1
#define MEMCHECK_ERROR 2

// Allocate more space for packet 'elements' if needed.
static int p_mutka_packet_memcheck(struct mutka_packet* packet) { 
    size_t old_num_elems_alloc = packet->num_elems_allocated;
    
    if(packet->num_elements+1 >= packet->num_elems_allocated) {
        packet->elements = mutka_srealloc_array(
                sizeof(*packet->elements), 
                packet->elements,
                &packet->num_elems_allocated,
                packet->num_elems_allocated + 1);

        if(old_num_elems_alloc >= packet->num_elems_allocated) {
            mutka_set_errmsg("Packet parser experienced unexpected memory error.");
            return MEMCHECK_ERROR;
        }

        for(size_t i = old_num_elems_alloc; i < packet->num_elems_allocated; i++) {
            packet->elements[i].encoding = 0;
            packet->elements[i].label.bytes = NULL;
            packet->elements[i].data.bytes = NULL;
        }
        return MEMCHECK_BUFRESIZED;
    }

    return MEMCHECK_NOACTNEEDED;
}

void mutka_clear_packet(struct mutka_packet* packet) {
    if(packet->elements) {
        for(uint32_t i = 0; i < packet->num_elements; i++) {
            struct mutka_packet_elem* elem = &packet->elements[i];
            mutka_str_clear(&elem->label);
            mutka_str_clear(&elem->data);
        }
    }    

    packet->expected_size = 0;
    packet->num_elements = 0;
    packet->id = -1;
}

static bool p_is_rpacket_data_safe(struct mutka_raw_packet* raw_packet) {
    bool result = false;

    if(raw_packet->memsize < raw_packet->size) {
        mutka_set_errmsg("Received packet has bad memory size.");
        goto out;
    }
    if(raw_packet->size < RPACKET_HEADER_SIZE) {
        mutka_set_errmsg("Received packet doesnt have good header.");
        goto out;
    }
    if(raw_packet->size == RPACKET_HEADER_SIZE) {
        result = true;
        goto out;
    }

    int index = 0;

    const char whitelist_bytes[] = {
        0x0,
        0x0A, // New line character.
        0x1,  // Encoding option (RPACKET_ENCODE_NONE)
        0x2   // Encoding option (RPACKET_ENCODE)
    };

    char* ch = &raw_packet->data[RPACKET_HEADER_SIZE];
    while(ch < raw_packet->data + raw_packet->size) {
        
        if((*ch < 0x20) || (*ch > 0x7E)) {
            bool good_byte = false;

            for(uint32_t i = 0; i < sizeof(whitelist_bytes); i++) {
                if(*ch == whitelist_bytes[i]) {
                    good_byte = true;
                }
            }

            if(!good_byte) {
                printf("%s: %02X at %i\n", __func__, (uint8_t)*ch, index);
                goto out;
            }
        }
        index++;
        ch++;
    }

    result = true;

out:
    return result;
}

bool mutka_parse_rpacket(struct mutka_packet* packet, struct mutka_raw_packet* raw_packet) {
#ifdef DEBUG
    p_dump_packet(raw_packet, "received");
#endif

    bool result = false;

    if(!p_is_rpacket_data_safe(raw_packet)) {
        mutka_set_errmsg("Received raw packet data seems to be somehow malformed.");
        goto out;
    }

    mutka_clear_packet(packet);
  
    size_t header_size = 0;

    memmove(&packet->expected_size, &raw_packet->data[header_size], sizeof(packet->expected_size));
    header_size += sizeof(packet->expected_size);
    
    memmove(&packet->id, &raw_packet->data[header_size], sizeof(packet->id));
    header_size += sizeof(packet->id);

    if(packet->id >= MUTKA_NUM_PACKETS) {
        mutka_set_errmsg("Packet has invalid id or it was not set.");
        goto out;
    }
    
    if(p_mutka_packet_memcheck(packet) == MEMCHECK_ERROR) {
        goto out;
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
            goto out;
        }

        curr_elem->encoding = (uint8_t)*ch;
        ch++;


        // Read element data:
        while(ch < lastch) {
            if(*ch == '|') { // Element separator.
                
                // Allocate more memory for the packet->elements if needed.
                int memcheck_res = p_mutka_packet_memcheck(packet);
                if(memcheck_res == MEMCHECK_ERROR) {
                    goto out;
                }
                if(memcheck_res == MEMCHECK_BUFRESIZED) {
                    // Update pointer if memory was realloced.
                    curr_elem = &packet->elements[packet->num_elements];
                }

                
                if(curr_elem->encoding == RPACKET_ENCODE) {
                    mutka_str_clear(&packet->tmp_decode_str);

                    size_t decoded_len = mutka_get_decoded_buffer_len(curr_elem->data.size);
                    mutka_str_reserve(&packet->tmp_decode_str, decoded_len);
                    
                    if(!mutka_decode(
                                (uint8_t*)packet->tmp_decode_str.bytes,
                                packet->tmp_decode_str.memsize,
                                curr_elem->data.bytes,
                                curr_elem->data.size)) {
                        mutka_set_errmsg("%s: Failed to decode %s data. Packet ID = %i",
                                __func__, packet->id);
                        goto out;
                    }

                    packet->tmp_decode_str.size = decoded_len;

                    mutka_str_move(
                            &curr_elem->data,
                            packet->tmp_decode_str.bytes,
                            packet->tmp_decode_str.size);
                }
                else
                if(curr_elem->encoding == RPACKET_ENCODE_NONE) {
                    mutka_str_nullterm(&curr_elem->data);
                }
                else {
                    mutka_set_errmsg("%s: Unknown encoding option. Packet ID = %i",
                            __func__, packet->id);
                    goto out;
                }
                
                packet->num_elements++;
                if(packet->num_elements >= packet->num_elems_allocated) {
                    goto out;
                }

                curr_elem = &packet->elements[packet->num_elements];
                if(!curr_elem) {
                    goto out;
                }

                ch++;
                break;
            }

            mutka_str_pushbyte(&curr_elem->data, *ch);
            ch++;
        }
    }

    result = true;
out:
    mutka_str_clear(&packet->tmp_decode_str);
    return result;
}


void mutka_send_encrypted_rpacket
(
    int socket_fd,
    struct mutka_raw_packet* packet,
    key128bit_t* mtdata_hshared_key
){
    if(packet->has_write_error) {
        return;
    }

    if(!p_mutka_add_packet_expected_size(packet)) {
        return;
    }

#ifdef DEBUG
    p_dump_packet(packet, "Sent (Before encryption)");
#endif

    struct mutka_str cipher;
    struct mutka_str out;
    struct mutka_str encoded;

    uint8_t gcm_tag[AESGCM_TAG_LEN] = { 0 };
    uint8_t gcm_iv[AESGCM_IV_LEN] = { 0 };
    RAND_bytes(gcm_iv, sizeof(gcm_iv));


    mutka_str_alloc(&cipher);
    mutka_str_alloc(&out);
    mutka_str_alloc(&encoded);

    if(!mutka_openssl_AES256GCM_encrypt(
                &cipher,
                gcm_tag,
                mtdata_hshared_key->bytes,
                gcm_iv,
                MUTKA_VERSION_STR,
                MUTKA_VERSION_STR_LEN,
                packet->data,
                packet->size)) {
        mutka_set_errmsg("%s: Failed to encrypt packet.", __func__);
        goto free_and_out;
    }

    //mutka_str_append(&out, MUTKA_VERSION_STR, MUTKA_VERSION_STR_LEN);
    mutka_str_append(&out, (char*)gcm_iv,  sizeof(gcm_iv));
    mutka_str_append(&out, (char*)gcm_tag, sizeof(gcm_tag));
    mutka_str_append(&out, cipher.bytes, cipher.size);

    mutka_encode(&encoded, (uint8_t*)out.bytes, out.size);
   
    const int64_t tail = MUTKA_ENCRYPTED_PACKET_TAIL;
    mutka_str_append(&encoded, (char*)&tail, sizeof(tail));

    send(socket_fd, encoded.bytes, encoded.size, 0);


free_and_out:
    mutka_str_free(&cipher);
    mutka_str_free(&out);
    mutka_str_free(&encoded);
}

static bool p_is_encrypted_raw_packet(struct mutka_raw_packet* rpacket) {
    if(rpacket->size < MUTKA_ENCRYPTED_PACKET_TAIL_NBYTES) {
        return false;
    }

    int64_t tail = 0;
    memmove(&tail, 
            rpacket->data + (rpacket->size - MUTKA_ENCRYPTED_PACKET_TAIL_NBYTES),
            MUTKA_ENCRYPTED_PACKET_TAIL_NBYTES);

    return (tail == MUTKA_ENCRYPTED_PACKET_TAIL);
}


// Decrypts 'raw_packet' and calls 'mutka_parse_rpacket' if succesful.
bool mutka_parse_encrypted_rpacket
(
    struct mutka_packet* packet,
    struct mutka_raw_packet* raw_packet,
    key128bit_t* mtdata_hshared_key
){
    bool result = false;

    if(!p_is_encrypted_raw_packet(raw_packet)) {
        mutka_set_errmsg("%s: Encrypted packet doesnt contain expected tail.", __func__);
        goto out;
    }

    raw_packet->size -= MUTKA_ENCRYPTED_PACKET_TAIL_NBYTES;

    struct mutka_str plain_packet;
    mutka_str_alloc(&plain_packet);

    const size_t decoded_packet_size = mutka_get_decoded_buffer_len(raw_packet->size);
    uint8_t* decoded_packet = calloc(decoded_packet_size, sizeof *decoded_packet);

    if(!mutka_decode(
                decoded_packet,
                decoded_packet_size,
                raw_packet->data,
                raw_packet->size)) {
        mutka_set_errmsg("%s: Failed to decode cipher text.", __func__);
        goto free_and_out;
    }


    size_t offset = 0;

    uint8_t gcm_iv[AESGCM_IV_LEN] = { 0 };
    char    gcm_tag[AESGCM_TAG_LEN] = { 0 };

    // Read GCM IV.
    if(offset + sizeof(gcm_iv) >= decoded_packet_size) {
        mutka_set_errmsg("%s: Encrypted packet is smaller than expected. Missing gcm_iv, gcm_tag and cipher text.",
                __func__);
        goto free_and_out;
    }
    memmove(gcm_iv, decoded_packet + offset, sizeof(gcm_iv));
    offset += sizeof(gcm_iv);


    // Read GCM TAG.
    if(offset + sizeof(gcm_tag) >= decoded_packet_size) {
        mutka_set_errmsg("%s: Encrypted packet is smaller than expected. Missing gcm_tag and cipher text.",
                __func__);
        goto free_and_out;
    }
    memmove(gcm_tag, decoded_packet + offset, sizeof(gcm_tag));
    offset += sizeof(gcm_tag);


    const int64_t remaining = (decoded_packet_size - offset);

    // Should never be true but maybe good idea to check just in case.
    if(remaining <= 0) {
        mutka_set_errmsg("%s: Encrypted packet is smaller than expected. Missing cipher text.",
                __func__);
        goto free_and_out;
    }

    if(remaining > 1024*64) {
        mutka_set_errmsg("%s: Remaining cipher text seems to be too large to accept.", __func__);
        goto free_and_out;
    }
   
    if((decoded_packet + offset) + remaining > decoded_packet + decoded_packet_size) {
        mutka_set_errmsg("%s: Would overflow. (decoded_packet + offset) + remaining > decoded_packet + decoded_packet_size");
        goto free_and_out;
    }

    if(!mutka_openssl_AES256GCM_decrypt(
                &plain_packet,
                mtdata_hshared_key->bytes,
                gcm_iv,
                MUTKA_VERSION_STR,
                MUTKA_VERSION_STR_LEN,
                gcm_tag,
                sizeof(gcm_tag),
                (char*)(decoded_packet + offset),
                remaining)) {
        mutka_set_errmsg("%s: Failed to decrypt packet.", __func__);
        goto free_and_out;
    }


    if(plain_packet.size >= raw_packet->memsize) {
        mutka_set_errmsg("%s: Decrypted packet size seems to be too large.", __func__);
        goto free_and_out;
    }

    // Move the decrypted packet data into raw_packet
    // It can then be parsed normally.

    memmove(raw_packet->data, plain_packet.bytes, plain_packet.size);
    raw_packet->size = plain_packet.size;

    result = mutka_parse_rpacket(packet, raw_packet);


free_and_out:
    mutka_str_free(&plain_packet);
    free(decoded_packet);
out:
    return result;
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

    if(p_is_encrypted_raw_packet(&packet->raw_packet)) {
        return M_ENCRYPTED_RPACKET;
    }

    if(!mutka_parse_rpacket(packet, &packet->raw_packet)) {
        return M_PACKET_PARSE_ERR;
    }

    return M_NEW_PACKET_AVAIL;
}

void mutka_replace_inpacket_id
(
    struct mutka_packet* inpacket,
    int new_packet_id
){

    if(!inpacket->raw_packet.data) {
        return;
    }

    if(inpacket->raw_packet.size < sizeof(new_packet_id)) {
        return;
    }


    // The inpacket->raw_packet contains expected size at beginning of data.
    // It must be removed first.

    memmove(inpacket->raw_packet.data,
            inpacket->raw_packet.data + sizeof(int),
            inpacket->raw_packet.size - sizeof(int));
    inpacket->raw_packet.size -= sizeof(int);


    memcpy(inpacket->raw_packet.data,
            &new_packet_id,
            sizeof(new_packet_id));
}

const char* mutka_get_packet_name(int packet_id) {
    return "MUTKA_GET_PACKET_NAME() NOT IMPLEMENTED";
}


bool mutka_validate_parsed_packet(struct mpacket_data* packet_struct, struct mutka_packet* inpacket) {
    packet_struct->packet_id = inpacket->id; // This will be useful for 'mutka_free_validated_packet'

    switch(inpacket->id) {

        case STOC_MPACKET_HOST_PUBLKEY:
            if(inpacket->num_elements != 1) {
                mutka_set_errmsg("%s: %s: Invalid number of elements.",
                        __func__, mutka_get_packet_name(inpacket->id));
                return false;
            }
            {
                struct mutka_packet_elem* host_publkey_elem = &inpacket->elements[0];

                struct STOC_HOST_PUBLKEY_struct* out_p = &packet_struct->STOC_HOST_PUBLKEY;


                if(host_publkey_elem->data.size != sizeof(out_p->host_publkey.bytes)) {
                    mutka_set_errmsg("%s: %s: Unexpected host public key length.", 
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }

                const float host_publkey_entropy = mutka_compute_key_entropy((uint8_t*)
                            host_publkey_elem->data.bytes,
                            host_publkey_elem->data.size);

                if(host_publkey_entropy < MLDSA87_ENTROPY_BIAS) {
                    mutka_set_errmsg("%s: %s: Host public key has too low entropy.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }


                memcpy(out_p->host_publkey.bytes,
                        host_publkey_elem->data.bytes,
                        host_publkey_elem->data.size);
            }
            break;


        case STOC_MPACKET_PEER_PUBLKEYS:
            if(inpacket->num_elements != 5) {
                mutka_set_errmsg("%s: %s: Invalid number of elements.", 
                        __func__, mutka_get_packet_name(inpacket->id));
                return false;
            }
            {
                struct mutka_packet_elem* peer_uid_elem            = &inpacket->elements[0];
                struct mutka_packet_elem* identity_publkey_elem    = &inpacket->elements[1];
                struct mutka_packet_elem* mlkem_publkey_elem       = &inpacket->elements[2];
                struct mutka_packet_elem* x25519_publkey_elem      = &inpacket->elements[3];
                struct mutka_packet_elem* signature_elem           = &inpacket->elements[4];
                
                struct STOC_PEER_PUBLKEYS_struct* out_p = &packet_struct->STOC_PEER_PUBLKEYS;
 

                if(peer_uid_elem->data.size != sizeof(out_p->peer_uid)) {
                    mutka_set_errmsg("%s: %s: Unexpected peer uid length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(identity_publkey_elem->data.size != sizeof(out_p->identity_publkey.bytes)) {
                    mutka_set_errmsg("%s: %s: Unexpected peer identity public key length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(mlkem_publkey_elem->data.size != sizeof(out_p->mlkem_publkey.bytes)) {
                    mutka_set_errmsg("%s: %s: Unexpected peer ML-KEM-1024 public key length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(x25519_publkey_elem->data.size != sizeof(out_p->x25519_publkey.bytes)) {
                    mutka_set_errmsg("%s: %s: Unexpected peer X25519 public key length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(signature_elem->data.size != sizeof(out_p->signature.bytes)) {
                    mutka_set_errmsg("%s: %s: Unexpected signature length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }

                const float identity_publkey_entropy = mutka_compute_key_entropy((uint8_t*)
                            identity_publkey_elem->data.bytes,
                            identity_publkey_elem->data.size);

                const float mlkem_publkey_entropy = mutka_compute_key_entropy((uint8_t*)
                            mlkem_publkey_elem->data.bytes,
                            mlkem_publkey_elem->data.size);

                const float x25519_publkey_entropy = mutka_compute_key_entropy((uint8_t*)
                            x25519_publkey_elem->data.bytes,
                            x25519_publkey_elem->data.size);

                if(identity_publkey_entropy < MLDSA87_ENTROPY_BIAS) {
                    mutka_set_errmsg("%s: %s: Identity public key has too low entropy.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }

                if(mlkem_publkey_entropy < MLKEM1024_ENTROPY_BIAS) {
                    mutka_set_errmsg("%s: %s: ML-KEM-1024 public key has too low entropy.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }

                if(x25519_publkey_entropy < X25519_ENTROPY_BIAS) {
                    mutka_set_errmsg("%s: %s: X25519 public key has too low entropy.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }

                memcpy(&out_p->peer_uid,
                        peer_uid_elem->data.bytes,
                        peer_uid_elem->data.size);

                memcpy(out_p->identity_publkey.bytes,
                        identity_publkey_elem->data.bytes,
                        identity_publkey_elem->data.size);

                memcpy(out_p->mlkem_publkey.bytes,
                        mlkem_publkey_elem->data.bytes,
                        mlkem_publkey_elem->data.size);

                memcpy(out_p->signature.bytes,
                        signature_elem->data.bytes,
                        signature_elem->data.size);
            }
            break;


        case STOC_MPACKET_EXCH_METADATA_KEYS:
            if(inpacket->num_elements != 4) {
                mutka_set_errmsg("%s: %s: Invalid number of elements.", 
                        __func__, mutka_get_packet_name(inpacket->id));
                return false;
            }
            {
                struct mutka_packet_elem* x25519_publkey_elem  = &inpacket->elements[0];
                struct mutka_packet_elem* mlkem_cipher_elem    = &inpacket->elements[1];
                struct mutka_packet_elem* signature_elem       = &inpacket->elements[2];
                struct mutka_packet_elem* hkdf_salt_elem       = &inpacket->elements[3];
                
                struct STOC_EXCH_METADATA_KEYS_struct* out_p = &packet_struct->STOC_EXCH_METADATA_KEYS;


                if(x25519_publkey_elem->data.size != sizeof(out_p->peer_x25519_publkey.bytes)) {
                     mutka_set_errmsg("%s: %s: Unexpected peer X25519 public key length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(mlkem_cipher_elem->data.size != sizeof(out_p->peer_mlkem_cipher.bytes)) {
                     mutka_set_errmsg("%s: %s: Unexpected peer ML-KEM-1024 cipher length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(signature_elem->data.size != sizeof(out_p->signature.bytes)) {
                     mutka_set_errmsg("%s: %s: Unexpected signature length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(hkdf_salt_elem->data.size != sizeof(out_p->hkdf_salt)) {
                     mutka_set_errmsg("%s: %s: Unexpected HKDF salt length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }

                const float x25519_publkey_entropy = mutka_compute_key_entropy((uint8_t*)
                            x25519_publkey_elem->data.bytes,
                            x25519_publkey_elem->data.size);

                const float mlkem_cipher_entropy = mutka_compute_key_entropy((uint8_t*)
                            mlkem_cipher_elem->data.bytes,
                            mlkem_cipher_elem->data.size);

                if(x25519_publkey_entropy < X25519_ENTROPY_BIAS) {
                    mutka_set_errmsg("%s: %s: Peer X25519 public key has too low entropy.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }

                if(mlkem_cipher_entropy < MLKEM1024_ENTROPY_BIAS) {
                    mutka_set_errmsg("%s: %s: Peer ML-KEM-1024 cipher has too low entropy.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }

                memcpy(out_p->peer_x25519_publkey.bytes,
                        x25519_publkey_elem->data.bytes,
                        x25519_publkey_elem->data.size);

                memcpy(out_p->peer_mlkem_cipher.bytes,
                        mlkem_cipher_elem->data.bytes,
                        mlkem_cipher_elem->data.size);

                memcpy(out_p->signature.bytes,
                        signature_elem->data.bytes,
                        signature_elem->data.size);

                memcpy(out_p->hkdf_salt,
                        hkdf_salt_elem->data.bytes,
                        hkdf_salt_elem->data.size);

            }
            break;

        case CTOS_MPACKET_EXCH_METADATA_KEYS:
            if(inpacket->num_elements != 2) {
                mutka_set_errmsg("%s: %s: Invalid number of elements.", 
                        __func__, mutka_get_packet_name(inpacket->id));
                return false;
            }
            {
                struct mutka_packet_elem* x25519_publkey_elem  = &inpacket->elements[0];
                struct mutka_packet_elem* mlkem_publkey_elem    = &inpacket->elements[1];
                
                struct CTOS_EXCH_METADATA_KEYS_struct* out_p = &packet_struct->CTOS_EXCH_METADATA_KEYS;


                if(x25519_publkey_elem->data.size != sizeof(out_p->peer_x25519_publkey.bytes)) {
                    mutka_set_errmsg("%s: %s: Unexpected peer X25519 public key length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(mlkem_publkey_elem->data.size != sizeof(out_p->peer_mlkem_publkey.bytes)) {
                    mutka_set_errmsg("%s: %s: Unexpected peer ML-KEM-1024 public key length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }

                const float x25519_publkey_entropy = mutka_compute_key_entropy((uint8_t*)
                            x25519_publkey_elem->data.bytes,
                            x25519_publkey_elem->data.size);

                const float mlkem_publkey_entropy = mutka_compute_key_entropy((uint8_t*)
                            mlkem_publkey_elem->data.bytes,
                            mlkem_publkey_elem->data.size);

                if(x25519_publkey_entropy < X25519_ENTROPY_BIAS) {
                    mutka_set_errmsg("%s: %s: Peer X25519 public key has too low entropy.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }

                if(mlkem_publkey_entropy < MLKEM1024_ENTROPY_BIAS) {
                    mutka_set_errmsg("%s: %s: Peer ML-KEM-1024 public key has too low entropy.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }

                memcpy(out_p->peer_x25519_publkey.bytes,
                        x25519_publkey_elem->data.bytes,
                        x25519_publkey_elem->data.size);

                memcpy(out_p->peer_mlkem_publkey.bytes,
                        mlkem_publkey_elem->data.bytes,
                        mlkem_publkey_elem->data.size);

            }
            break;

        case CTOS_MPACKET_DEPOSIT_PUBLIC_MSGKEYS:
            if(inpacket->num_elements != 4) {
                mutka_set_errmsg("%s: %s: Invalid number of elements.", 
                        __func__, mutka_get_packet_name(inpacket->id));
                return false;
            }
            {
                struct mutka_packet_elem* identity_publkey_elem = &inpacket->elements[0];
                struct mutka_packet_elem* x25519_publkey_elem   = &inpacket->elements[1];
                struct mutka_packet_elem* mlkem_publkey_elem    = &inpacket->elements[2];
                struct mutka_packet_elem* signature_elem        = &inpacket->elements[3];
                
                struct CTOS_DEPOSIT_PUBLIC_MSGKEYS_struct* out_p = &packet_struct->CTOS_DEPOSIT_PUBLIC_MSGKEYS;


                if(identity_publkey_elem->data.size != sizeof(out_p->identity_publkey.bytes)) {
                    mutka_set_errmsg("%s: %s: Unexpected Identity public key length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(x25519_publkey_elem->data.size != sizeof(out_p->x25519_publkey.bytes)) {
                     mutka_set_errmsg("%s: %s: Unexpected X25519 public key length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(mlkem_publkey_elem->data.size != sizeof(out_p->mlkem_publkey.bytes)) {
                     mutka_set_errmsg("%s: %s: Unexpected ML-KEM-1024 public key length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(signature_elem->data.size != sizeof(out_p->signature.bytes)) {
                     mutka_set_errmsg("%s: %s: Unexpected signature length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }


                const float identity_publkey_entropy = mutka_compute_key_entropy((uint8_t*)
                            identity_publkey_elem->data.bytes,
                            identity_publkey_elem->data.size);

                const float x25519_publkey_entropy = mutka_compute_key_entropy((uint8_t*)
                            x25519_publkey_elem->data.bytes,
                            x25519_publkey_elem->data.size);

                const float mlkem_publkey_entropy = mutka_compute_key_entropy((uint8_t*)
                            mlkem_publkey_elem->data.bytes,
                            mlkem_publkey_elem->data.size);

                if(identity_publkey_entropy < MLDSA87_ENTROPY_BIAS) {
                    mutka_set_errmsg("%s: %s: Identity public key has too low entropy.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }

                if(x25519_publkey_entropy < X25519_ENTROPY_BIAS) {
                    mutka_set_errmsg("%s: %s: X25519 public key has too low entropy.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }

                if(mlkem_publkey_entropy < MLKEM1024_ENTROPY_BIAS) {
                    mutka_set_errmsg("%s: %s: ML-KEM-1024 public key has too low entropy.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }

                memcpy(out_p->identity_publkey.bytes,
                        identity_publkey_elem->data.bytes,
                        identity_publkey_elem->data.size);

                memcpy(out_p->x25519_publkey.bytes,
                        x25519_publkey_elem->data.bytes,
                        x25519_publkey_elem->data.size);

                memcpy(out_p->mlkem_publkey.bytes,
                        mlkem_publkey_elem->data.bytes,
                        mlkem_publkey_elem->data.size);

                memcpy(out_p->signature.bytes,
                        signature_elem->data.bytes,
                        signature_elem->data.size);
            }
            break;


        case CTOS_MPACKET_SEND_MSG_CIPHER:
            if(inpacket->num_elements != 10) {
                mutka_set_errmsg("%s: %s: Invalid number of elements.", 
                        __func__, mutka_get_packet_name(inpacket->id));
                return false;
            }
            {
                struct mutka_packet_elem* receiver_uid_elem      = &inpacket->elements[0];
                struct mutka_packet_elem* msg_cipher_elem        = &inpacket->elements[1];
                struct mutka_packet_elem* gcm_aad_elem           = &inpacket->elements[2];
                struct mutka_packet_elem* gcm_iv_elem            = &inpacket->elements[3];
                struct mutka_packet_elem* gcm_tag_elem           = &inpacket->elements[4];
                struct mutka_packet_elem* hkdf_salt_elem         = &inpacket->elements[5];
                struct mutka_packet_elem* identity_publkey_elem  = &inpacket->elements[6];
                struct mutka_packet_elem* x25519_publkey_elem    = &inpacket->elements[7];
                struct mutka_packet_elem* mlkem_cipher_elem      = &inpacket->elements[8];
                struct mutka_packet_elem* signature_elem         = &inpacket->elements[9];

                struct CTOS_SEND_MSG_CIPHER_struct* out_p = &packet_struct->CTOS_SEND_MSG_CIPHER;

                // NOTE: Message cipher and gcm_aad length dont matter.

                if(receiver_uid_elem->data.size != sizeof(out_p->receiver_uid)) {
                    mutka_set_errmsg("%s: %s: Unexpected receiver uid length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(gcm_iv_elem->data.size != sizeof(out_p->gcm_iv)) {
                    mutka_set_errmsg("%s: %s: Unexpected GCM IV length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(gcm_tag_elem->data.size != sizeof(out_p->gcm_tag)) {
                    mutka_set_errmsg("%s: %s: Unexpected GCM TAG length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(hkdf_salt_elem->data.size != sizeof(out_p->hkdf_salt)) {
                    mutka_set_errmsg("%s: %s: Unexpected HKDF salt length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(identity_publkey_elem->data.size != sizeof(out_p->identity_publkey.bytes)) {
                    mutka_set_errmsg("%s: %s: Unexpected identity public key length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(x25519_publkey_elem->data.size != sizeof(out_p->x25519_publkey.bytes)) {
                    mutka_set_errmsg("%s: %s: Unexpected X25519 public key length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(mlkem_cipher_elem->data.size != sizeof(out_p->mlkem_cipher.bytes)) {
                    mutka_set_errmsg("%s: %s: Unexpected ML-KEM-1024 cipher key length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(signature_elem->data.size != sizeof(out_p->signature.bytes)) {
                    mutka_set_errmsg("%s: %s: Unexpected signature length.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }


                const float identity_publkey_entropy = mutka_compute_key_entropy((uint8_t*)
                            identity_publkey_elem->data.bytes,
                            identity_publkey_elem->data.size);

                const float x25519_publkey_entropy = mutka_compute_key_entropy((uint8_t*)
                            x25519_publkey_elem->data.bytes,
                            x25519_publkey_elem->data.size);

                const float mlkem_cipher_entropy = mutka_compute_key_entropy((uint8_t*)
                            mlkem_cipher_elem->data.bytes,
                            mlkem_cipher_elem->data.size);

                if(identity_publkey_entropy < MLDSA87_ENTROPY_BIAS) {
                    mutka_set_errmsg("%s: %s: Identity public key has too low entropy.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(x25519_publkey_entropy < X25519_ENTROPY_BIAS) {
                    mutka_set_errmsg("%s: %s: X25519 public key has too low entropy.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }
                if(mlkem_cipher_entropy < MLKEM1024_ENTROPY_BIAS) {
                    mutka_set_errmsg("%s: %s: ML-KEM-1024 cipher has too low entropy.",
                            __func__, mutka_get_packet_name(inpacket->id));
                    return false;
                }


                memcpy(&out_p->receiver_uid,
                        receiver_uid_elem->data.bytes,
                        receiver_uid_elem->data.size);

                // TODO: Set msg cipher, gcm_aad...
                
                memcpy(out_p->gcm_iv,
                        gcm_iv_elem->data.bytes,
                        gcm_iv_elem->data.size);
            
                memcpy(out_p->gcm_tag,
                        gcm_tag_elem->data.bytes,
                        gcm_tag_elem->data.size);

                memcpy(out_p->hkdf_salt,
                        hkdf_salt_elem->data.bytes,
                        hkdf_salt_elem->data.size);

                memcpy(out_p->identity_publkey.bytes,
                        identity_publkey_elem->data.bytes,
                        identity_publkey_elem->data.size);

                memcpy(out_p->x25519_publkey.bytes,
                        x25519_publkey_elem->data.bytes,
                        x25519_publkey_elem->data.size);

                memcpy(out_p->mlkem_cipher.bytes,
                        mlkem_cipher_elem->data.bytes,
                        mlkem_cipher_elem->data.size);

                memcpy(out_p->signature.bytes,
                        signature_elem->data.bytes,
                        signature_elem->data.size);
            }
            break;

        case STOC_MPACKET_NEW_MSG_CIPHER:
            {
            }
            break;

        default:
            return false;
    }

    return true;
}


void mutka_free_validated_packet(struct mpacket_data* packet_data) {
    mutka_set_errmsg("%s: NOT IMPLEMENTED YET", __func__);
}





