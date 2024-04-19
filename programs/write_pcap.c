#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "write_pcap.h"

/* Ethernet header for IPv4, both source and dest are broadcast */
const unsigned char ethernet_header[] = {
    '\xff', '\xff', '\xff', '\xff', '\xff', '\xff',
    '\xff', '\xff', '\xff', '\xff', '\xff', '\xff',
    '\x08', '\x00'
};

static uint16_t inet_csum(const void *buf, size_t hdr_len);


void pcap_dump_udp(pcap_dumper_t* p, const void* payload, size_t length, bool outgoing)
{
    size_t packet_len = sizeof(ethernet_header) +
	sizeof(struct iphdr) +
	sizeof(struct udphdr) +
	length;
    unsigned char* packet = malloc(packet_len);
    if (packet == NULL)
	return;

    memcpy(packet, ethernet_header, sizeof(ethernet_header));
    struct iphdr* ip = (struct iphdr*)(packet + sizeof(ethernet_header));
    struct udphdr* udp = (struct udphdr*)(((char*)ip) + sizeof(struct iphdr));
    char* payload_loc = (char*)udp + sizeof(struct udphdr);
    memcpy(payload_loc, payload, length);

    in_addr_t localhost = inet_addr("127.0.0.1");
    in_addr_t remotehost = inet_addr("192.0.2.0");
    uint16_t localport = htons(55555);
    uint16_t remoteport = htons(9899);

    in_addr_t srchost, dsthost;
    uint16_t srcport, dstport;

    if (outgoing) {
	srchost = localhost;
	dsthost = remotehost;
	srcport = localport;
	dstport = remoteport;
    }
    else {
	srchost = remotehost;
	dsthost = localhost;
	srcport = remoteport;
	dstport = localport;
    }

    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0x0;
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + length);
    ip->protocol = IPPROTO_UDP;
    ip->saddr = srchost;
    ip->daddr = dsthost;

    ip->check = 0;
    ip->check = inet_csum(ip, sizeof(struct iphdr));

    udp->source = srcport;
    udp->dest = dstport;
    udp->len = htons(sizeof(struct udphdr) + length);
    udp->check = 0;

    struct pcap_pkthdr h;

    gettimeofday(&h.ts, NULL);
    h.caplen = packet_len;
    h.len = packet_len;

    pcap_dump((u_char*)p, &h, packet);

    free(packet);
}


static uint16_t inet_csum(const void *buf, size_t hdr_len)
{
  unsigned long sum = 0;
  const uint16_t *ip1;

  ip1 = (const uint16_t *) buf;
  while (hdr_len > 1)
  {
    sum += *ip1++;
    if (sum & 0x80000000)
      sum = (sum & 0xFFFF) + (sum >> 16);
    hdr_len -= 2;
  }

  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return(~sum);
}
