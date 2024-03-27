#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

#define IP_PRO 0x0800
#define TCP_PRO 6

//reference : https://nmap.org/book/tcpip-ref.html
//ip header struct 
//except options 

typedef struct {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_and_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src[4];
    uint8_t dst[4];
} ip_header, *ip_header_pointer;

//tcp header struct

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t offset_reserved;
    uint8_t tcp_flag;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
    /* options */
} tcp_header, *tcp_header_pointer;

//ethernet header struct
//reference : https://en.wikipedia.org/wiki/Ethernet_frame - Ethernet II 
//We can find some information about structure of Ethernet Header

typedef struct {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype;
} eth_header, *eth_header_pointer;

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		printf("%u bytes captured\n", header->caplen);

		eth_header_pointer eth_hdr = (eth_header_pointer) packet;
		//add ethernet header length to packet
		ip_header_pointer ip_hdr = (ip_header_pointer)(packet+14);
		if(ntohs(eth_hdr->ethertype) != IP_PRO){
			printf("It's not IP packet\n");
			continue;
		}
		if(ip_hdr->protocol != TCP_PRO){
			printf("It's not TCP packet\n");
			continue;
		}
		//ip header len (Nibble)
		u_int16_t ip_hdr_len = (ip_hdr->version_ihl & 0x0f) << 2;

		//TCP_header
		//pointer is 8 byte so using "uint8_t *"
		tcp_header_pointer tcp_hdr = (tcp_header_pointer)((uint8_t *)ip_hdr+ip_hdr_len); 
		//On the website, multiple to Offset by 4 to get byte count.
		uint16_t tcp_hdr_len = (tcp_hdr->offset_reserved >> 4) << 2;

		//payload for data
		uint8_t *payload = (uint8_t*)tcp_hdr + tcp_hdr_len;
		//get payload len
		uint16_t payload_len = ntohs(ip_hdr->total_length)-ip_hdr_len-tcp_hdr_len;

		//ETHERNET
		printf("1. ETHERNET\n");
		printf("\t src : ");
		for(int i = 0; i < 6; i++){
			printf("%02x",eth_hdr->src[i]);
		}
		printf("\n");
		printf("\t dst : ");
		for(int i = 0; i < 6; i++){
			printf("%02x",eth_hdr->dst[i]);
		}
		printf("\n");

		// IP
		printf("2. IP\n");
		printf("\t src ip : ");
		for(int i = 0; i < 4; i++){
			printf("%02x",eth_hdr->src[i]);
		}
		printf("\n");
		printf("\t dst ip : ");
		for(int i = 0; i < 4; i++){
			printf("%02x",eth_hdr->dst[i]);
		}
		printf("\n");
		
		// TCP
		printf("3. TCP\n");
		printf("\t src : ");
		printf("%d\n",ntohs(tcp_hdr->dst_port));
		printf("\n");
		printf("\t dst : ");
		printf("%d\n",ntohs(tcp_hdr->dst_port));
		printf("\n");

		// payload
		for(int i = 0 ; i < payload_len; i++){
			if(i % 8 == 0){
				printf("\t");
				printf("%02x ",payload[i]);
			}
			if(i % 8 == 7){
				printf("\n");
			}
		}

	}

	pcap_close(pcap);
}
