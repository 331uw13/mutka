
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "../../../libmutka/include/mutka.h"






int main() {
    struct mutka_client* client = mutka_connect("127.0.0.1", 35580);
    if(!client) {
        fprintf(stderr, "ERROR: %s\n", mutka_get_errmsg());
        return 1;
    }


    mutka_rpacket_prep(&client->out_raw_packet, MPACKET_HANDSHAKE);
    mutka_rpacket_add_ent(&client->out_raw_packet, "testentry", "hello_world", 11);
    mutka_rpacket_add_ent(&client->out_raw_packet, "some other stuff", "watsup", 6);
    mutka_send_rpacket(client->socket_fd, &client->out_raw_packet);


    while(1) {

        int rd = mutka_recv_incoming_packet(&client->inpacket, client->socket_fd);
       
        if(rd > 0) {
         
            for(uint32_t i = 0; i < client->inpacket.num_elements; i++) {
                struct mutka_packet_elem* elem = &client->inpacket.elements[i];
                printf("%s:%s\n", elem->label.bytes, elem->data.bytes);
            }

            break;
        }
        else 
        if(rd < 0) {
            printf("ERROR: %s\n", mutka_get_errmsg());
            continue;
        }
        
    }

   
    mutka_disconnect(client);
    return 0;
}




