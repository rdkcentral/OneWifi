/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#define ETH_P_1905 0x893a
#define BUF_SIZE 1500

struct ieee1905_header {
    uint8_t version;
    uint16_t message_type;
    uint16_t message_id;
    uint8_t fragment_id;
    uint8_t flags;
} __attribute__((packed));

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_1905));
    if (sock < 0) { perror("socket"); return 1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); return 1; }

    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_1905);
    addr.sll_ifindex = ifr.ifr_ifindex;
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }

    printf("Listening on %s for 1905.1 packets...\n", ifname);

    unsigned char buffer[BUF_SIZE];
    while (1) {
        ssize_t len = recvfrom(sock, buffer, BUF_SIZE, 0, NULL, NULL);
        if (len < 0) { perror("recvfrom"); continue; }

        struct ether_header *eth = (struct ether_header *)buffer;
        if (ntohs(eth->ether_type) != ETH_P_1905) continue;

        struct ieee1905_header *hdr = (struct ieee1905_header *)(buffer + sizeof(struct ether_header));
        printf("\nReceived 1905.1 packet:\n");
        printf("  Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
               eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        printf("  Message Type: 0x%04x\n", ntohs(hdr->message_type));
        printf("  Message ID: %u\n", ntohs(hdr->message_id));
    }

    close(sock);
    return 0;
}
