/*
 * Copyright (c) 2015, Joshua Wright <jwright@willhackforsushi.com>
 *
 * $Id: $
 *
 * See the LICENSE file for license details.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <wtap.h>
#include "nm2lp.h"
#include "common.h"
#include "utils.h"

int main(int argc, char **argv) {

	struct wtap *wtap = NULL;
	pcap_t *p;
	pcap_dumper_t *pd;
	struct pcap_pkthdr h;
	int pcount=0, skipcount=0, hdroffset=0;
	int err, linktype, pplinktype;
	gint64 offset;
	char *err_info;

	const struct wtap_pkthdr *packet_header;
	const uint8_t *packet_data;

	printf("nm2lp: Convert NetMon Wireless Packet Captures to Libpcap Format (v1.2)\n");
	printf("Copyright (c) 2015 Joshua Wright <jwright@willhackforsushi.com>\n");
	if (argc < 3) {
		fprintf(stderr, "Usage: nm2lp <infile.cap> <outfile.pcap>\n");
		return 1;
	}

/*
   Wireshark 1.12 changed the wiretap API. Check for WTAP_TYPE_AUTO to test
   for API 1.12 and later, else handle the earlier API.
*/
#ifdef WTAP_TYPE_AUTO
	wtap = wtap_open_offline(argv[1], WTAP_TYPE_AUTO, &err, &err_info, FALSE);
#else
	wtap = wtap_open_offline(argv[1], &err, &err_info, FALSE);
#endif
	if (wtap == NULL) {
		fprintf(stderr, "Cannot open NetMon packet capture file \"%s\" (error %d)\n", argv[1], err);
		if (err_info != NULL) {
			fprintf(stderr, "%s\n", err_info);
		}
		return 1;
	}

	linktype = wtap_file_encap(wtap);
	if (linktype != WTAP_ENCAP_IEEE_802_11 && 
			linktype != WTAP_ENCAP_IEEE_802_11_WITH_RADIO &&
			linktype != WTAP_ENCAP_PER_PACKET &&
			linktype != WTAP_ENCAP_IEEE_802_11_NETMON) {
        	fprintf(stderr, "Netmon file is not an 802.11 capture (encap: %d)\n", linktype);
        	return -1;
	}

	if (!(p = pcap_open_dead(DLT_IEEE802_11, SNAPLEN))) {
		fprintf(stderr, "Error opening pseudo libpcap interface.\n");
		return -1;
	}

	pd = pcap_dump_open(p, argv[2]);
	if (pd == NULL) {
		fprintf(stderr, "Cannot open output libpcap file \"%s\": %s.\n", argv[2], pcap_geterr(p));
		return -1;
	}

	while (wtap_read(wtap, &err, &err_info, &offset)) {
		packet_header = wtap_phdr(wtap);
		if (packet_header == NULL) {
			fprintf(stderr, "Cannot read header from file source for packet %d.\n", pcount);
			return -1;
		}

		/* If NetMon capture used per-packet encapsulation, check the encapsulation for this packet */
		if (linktype == WTAP_ENCAP_PER_PACKET) {
			pplinktype = packet_header->pkt_encap;
			if (pplinktype != WTAP_ENCAP_IEEE_802_11 && 
					pplinktype != WTAP_ENCAP_IEEE_802_11_WITH_RADIO &&
					pplinktype != WTAP_ENCAP_IEEE_802_11_NETMON) {
				//printf("DEBUG: Skipping packet with encap %d\n",pplinktype);
				skipcount+=1;
				continue;
			}
		} else {
			pplinktype=linktype;
		}

		packet_data = wtap_buf_ptr(wtap);

		if (packet_data == NULL) {
			fprintf(stderr, "Cannot read data from file source for packet %d.\n", pcount);
			return -1;
		}
		pcount+=1;

		/*
                   Using the link type, determine where the actual 802.11 packet starts, skipping any
                   NetMon header information.  XXX This needs to be updated to accommodate
		   WTAP_ENCAP_IEEE_802_11_WITH_RADIO.
                */
		switch(pplinktype) {
			case WTAP_ENCAP_IEEE_802_11:
				hdroffset=0;
				break;
			case WTAP_ENCAP_IEEE_802_11_NETMON:
				hdroffset=32;
				break;
			default:
				fprintf(stderr, "Cannot accommodate per-packet link type %d\n", pplinktype);
				return -1;
				break;
		}
		
		memset(&h, 0, sizeof(h));
		h.ts.tv_sec = packet_header->ts.secs;
		h.ts.tv_usec = packet_header->ts.nsecs/1000;
		h.caplen = packet_header->caplen-hdroffset;
		h.len = packet_header->len-hdroffset;
		pcap_dump((u_char *)pd, &h, packet_data+hdroffset);;

		//lamont_hdump(packet_data,packet_header->caplen);
	}

	printf("Processed %d packets, skipped %d.\n", pcount, skipcount);
	pcap_close(p);
	pcap_dump_close(pd);
	wtap_close(wtap);
	return 0;
}
