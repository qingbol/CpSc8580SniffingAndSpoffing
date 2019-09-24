/*
 * sniffex.c
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 *
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 ****************************************************************************
*/
/*  Copyright (C) 2011-2015  P.D. Buchan (pdbuchan@yahoo.com)
 
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// Send an IPv4 ICMP packet via raw socket.
// Stack fills out layer 2 (data link) information (MAC addresses) for us.
// Values set for echo request packet, includes some ICMP data.

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <features.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <sys/time.h>
#include <netinet/ether.h>
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
//END SNIFFEX DEFINES
//START SPOOFER
//#define DATA_SIZE  100
#define ICMP_TYPE  8

#define SRC_ETHER_ADDR	"98:90:96:e2:0c:74"
#define DST_ETHER_ADDR  "ff:ff:ff:ff:ff:ff"
// #define SRC_ETHER_ADDR "00:50:56:21:61:c4" //inet addr:172.16.166.154 
// #define DST_ETHER_ADDR "00:0c:29:02:1a:68"

#if 0
typedef struct PseudoHeader{

	unsigned long int source_ip;
	unsigned long int dest_ip;
	unsigned char reserved;
	unsigned char protocol;
	unsigned short int tcp_length;

}PseudoHeader;
#endif

typedef struct icmphdr
{
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned short identifier;
	unsigned short sequence;
	// char data[MTU];
} icmphdr;

//END SPOOFER

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* IP header */
struct sniff_icmp {
        u_int8_t  type;
        u_int8_t  code;
        u_int16_t checksum;
	u_int16_t id;
	u_int16_t seq;
};

char chszDev[32] = {0};




/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

int CreateRawSocket(int protocol_to_sniff)
{
	int rawsock;

	if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(protocol_to_sniff)))== -1)
	{
		perror("Error creating raw socket: ");
		exit(-1);
	}

	return rawsock;
}

int BindRawSocketToInterface(char *device, int rawsock, int protocol) {
	struct sockaddr_ll sll;
	struct ifreq ifr;
	bzero(&sll, sizeof(sll));
	bzero(&ifr, sizeof(ifr));
	/* First Get the Interface Index  */
	strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
	if((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1) {
		printf("Error getting Interface index !\n");
		exit(-1);
	}
	/* Bind our raw socket to this interface */
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(protocol);
	if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1) {
		perror("Error binding raw socket to interface\n");
		exit(-1);
	}
	return 1;
}


int SendRawPacket(int rawsock, unsigned char *pkt, int pkt_len) {
	int sent= 0;

	/* A simple write on the socket ..thats all it takes ! */
	if((sent = write(rawsock, pkt, pkt_len)) != pkt_len) {
		/* Error */
		printf("Could only send %d bytes of packet of length %d\n", sent, pkt_len);
		return 0;
	}

	return 1;
}

struct ethhdr* CreateEthernetHeader(char *src_mac, char *dst_mac, int protocol) {
	struct ethhdr *ethernet_header;
	ethernet_header = (struct ethhdr *)malloc(sizeof(struct ethhdr));

	/* copy the Src mac addr */
	memcpy(ethernet_header->h_source, (const void *)ether_aton(src_mac), 6);

	/* copy the Dst mac addr */
	memcpy(ethernet_header->h_dest, (const void *)ether_aton(dst_mac), 6);

	/* copy the protocol */
	ethernet_header->h_proto = htons(protocol);

	/* done ...send the header back */
	return (ethernet_header);
}

/* Ripped from Richard Stevans Book */
unsigned short ComputeChecksum(unsigned char *data, int len) {
  long sum = 0;  /* assume 32 bit long, 16 bit short */
	unsigned short *temp = (unsigned short *)data;

	while(len > 1){
			sum += *temp++;
			if(sum & 0x80000000)   /* if high order bit set, fold */
				sum = (sum & 0xFFFF) + (sum >> 16);
			len -= 2;
	}

	if(len)       /* take care of left over byte */
			sum += (unsigned short) *((unsigned char *)temp);

	while(sum>>16)
			sum = (sum & 0xFFFF) + (sum >> 16);

return ~sum;
}


struct iphdr* CreateIPHeader(char* src_ip, char* dst_ip)
{
	/******Construct Packet*****/
	struct iphdr* ip_header;

	ip_header = (struct iphdr* )malloc(sizeof(struct iphdr));

	ip_header->version = 4;
	ip_header->ihl = (sizeof(struct iphdr))/4 ;
	ip_header->tos = 0;
	ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 4);
	ip_header->id = htons(111);
	ip_header->frag_off = 0;
	ip_header->ttl = 111;
	ip_header->protocol = IPPROTO_ICMP;
	ip_header->check = 0; /* We will calculate the checksum later */
	ip_header->saddr = inet_addr(src_ip);
	ip_header->daddr = inet_addr(dst_ip);
	/* Calculate the IP checksum now :
	   The IP Checksum is only over the IP header */

	ip_header->check = ComputeChecksum((unsigned char *)ip_header, ip_header->ihl*4);

	return (ip_header);

}


/***Create ICMP Packet***/
struct icmphdr* CreateIcmpHeader(u_int16_t ID, u_int16_t seq) {
	icmphdr* icmp_header = (struct icmphdr*)malloc( sizeof(struct icmphdr) );

	//populate icmp
	icmp_header->code = 0;
	icmp_header->type = 0;
	icmp_header->sequence = seq; //Why rand()??
	icmp_header->checksum = 0;
	icmp_header->identifier = ID; //Again, why?
	// icmp_header->data = NULL; //Nothing is in the data field currently

	//checksum
	icmp_header->checksum = ComputeChecksum((unsigned char *)icmp_header, (sizeof (struct icmphdr)) );

	return (icmp_header);
}

unsigned char* CreateData(int len)
{
	char* data = ( char* )malloc(len);
	int counter = len;
	for(counter = 0 ; counter < len; counter++)
		data[counter] = 0;
	sprintf(data, "fake");

	return data;
}


//END SPOOFER
//START SNIFFEX MAIN

int main(int argc, char **argv) {
  printf("Sniff then Spoof program is working \n");
	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "icmp";
	// or (src host 10.0.2.20 and dst host 10.0.2.4)";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 10;			/* number of packets to capture */

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	int producePackets(char* src_ip, char* dst_ip, u_int16_t ID, u_int16_t seq) {
			printf("     Time to produce response packet from %s to %s\n", src_ip, dst_ip);
			int raw;
			unsigned char* packet;
			struct ethhdr* ethernet_header;
			struct iphdr* ip_header;
			//	struct tcphdr* tcp_header;
			struct icmphdr* icmp_header;
			unsigned char* data;
			int pkt_len;
			/******Get src/dest IP addr*****/
			/* Create the raw socket */
			raw = CreateRawSocket(ETH_P_ALL);
			/* Bind raw socket to interface */
			BindRawSocketToInterface(chszDev, raw, ETH_P_ALL);
			/* create Ethernet header */
			ethernet_header = CreateEthernetHeader(SRC_ETHER_ADDR, DST_ETHER_ADDR, ETHERTYPE_IP);
			/* Create IP Header */
			ip_header = CreateIPHeader(src_ip,dst_ip);
			/* Create ICMP Header */
			icmp_header = CreateIcmpHeader(ID, seq);
			/* Create Data */
			data = CreateData(4);
			/* Packet length = ETH + IP header + TCP header + Data*/
			pkt_len = sizeof(struct ethhdr) + ntohs(ip_header->tot_len);
			/* Allocate memory */
			packet = (unsigned char *)malloc(pkt_len);
			/* Copy the Ethernet header first */
			memcpy(packet, ethernet_header, sizeof(struct ethhdr));
			/* Copy the IP header -- but after the ethernet header */
			memcpy((packet + sizeof(struct ethhdr)), ip_header, ip_header->ihl*4);
			/* Copy the ICMP header after the IP header */
			memcpy((packet + sizeof(struct ethhdr) + ip_header->ihl*4), icmp_header, sizeof(struct icmphdr) );
			/* Copy the Data after the ICMP header */
			memcpy((packet + sizeof(struct ethhdr) + ip_header->ihl*4 + sizeof(struct icmphdr)), data, 4);
			/* send the packet on the wire */
			if(!SendRawPacket(raw, packet, pkt_len)) {
					perror("Error sending packet");
			} else
					printf("Packet sent successfully\n");
			/* Free the headers back to the heavenly heap */
			free(ethernet_header);
			free(ip_header);
			free(icmp_header);
			free(data);
			free(packet);
			close(raw);
			return 0;
	}

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	sprintf(chszDev, "%s", dev);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

 
	void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
        static int count = 1;                   /* packet counter */

        /* declare pointers to packet headers */
        const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
        const struct sniff_ip *ip;              /* The IP header */
			//	const struct sniff_tcp *tcp;            /* The TCP header */
        const struct sniff_icmp *icmp;
        const char *payload;                    /* Packet payload */

        int size_ip;
        int size_icmp;
        int size_payload;

        count++;

        /* define ethernet header */
        ethernet = (struct sniff_ethernet*)(packet);

        /* define/compute ip header offset */
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
            printf("   * Invalid IP header length: %u bytes\n", size_ip);
            return;
        }
        if(ip->ip_p != IPPROTO_ICMP) {
            return;
        }
        icmp = (struct sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);

        printf("\nPacket number %d:\n", count);
        char chszSrc[40] = {0};
        char chszDst[40] = {0};
        sprintf(chszSrc, "%s", inet_ntoa(ip->ip_src));
        sprintf(chszDst, "%s", inet_ntoa(ip->ip_dst));
        /* print source and destination IP addresses */
        printf("       From: %s\n", inet_ntoa(ip->ip_src));
        printf("         To: %s\n", inet_ntoa(ip->ip_dst));
        printf("         Type: %d; Code: %d; ID: %d; Seq: %d;\n", icmp->type, icmp->code, icmp->id, icmp->seq);
        if(icmp->type==0)
            return;
        producePackets(chszDst, chszSrc, icmp->id, icmp->seq);
  }
    
	/* now we can set our callback function */
	pcap_loop(handle, -1, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

	return 0;
}
