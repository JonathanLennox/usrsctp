#ifndef WRITE_PCAP_H
#define WRITE_PCAP_H

#include <stdbool.h>
#include <stdint.h>
#include <pcap.h>

#ifdef __cplusplus
extern "C" {
#endif

void pcap_dump_udp(pcap_dumper_t* p, const void* payload, size_t length, bool outgoing);

#ifdef __cplusplus
}
#endif

#endif
