
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "../../../libmutka/include/mutka.h"
#include "../../../libmutka/include/cryptography.h"




void packet_received(struct mutka_client* client) {
   
    printf("\033[32m%s\033[0m\n", __func__);

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


    printf("press enter to disconnect\n");
    char tmp = 0;
    read(1, &tmp, 1);

   
    mutka_disconnect(client);
    return 0;
}




