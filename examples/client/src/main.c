
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "../../../libmutka/include/mutka.h"
#include "../../../libmutka/include/cryptography.h"




void packet_received(struct mutka_client* client) {
   
    printf("%s\n", __func__);

    for(uint32_t i = 0; i < client->inpacket.num_elements; i++) {
        struct mutka_packet_elem* elem = &client->inpacket.elements[i];
        printf("[%i] -> %s:%s\n", i, elem->label.bytes, elem->data.bytes);
    }

}



int main() {
    struct mutka_client* client = mutka_connect("127.0.0.1", 35580);
    if(!client) {
        fprintf(stderr, "ERROR: %s\n", mutka_get_errmsg());
        return 1;
    }

    client->packet_received_callback = packet_received;

    mutka_rpacket_prep(&client->out_raw_packet, MPACKET_HANDSHAKE);
    mutka_rpacket_add_ent(&client->out_raw_packet, "testentry", "hello_world", 11);
    mutka_rpacket_add_ent(&client->out_raw_packet, "some other stuff", "watsup", 6);
    mutka_send_rpacket(client->socket_fd, &client->out_raw_packet);



    printf("press enter to disconnect\n");
    char tmp = 0;
    read(1, &tmp, 1);

   
    mutka_disconnect(client);
    return 0;
}




