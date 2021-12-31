#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

int id=1;

void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    
    ethernetHeader = (struct ether_header*)packet;
    //printf("%2x\n",ethernetHeader->ether_dhost);

	//int * id = (int *)arg,i;
	int i;
	printf("id: %d\n", id++);
	printf("Pack length: %d\n", pkthdr->len);
	printf("Number of bytes: %d\n", pkthdr->caplen);
	printf("Recieve time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec)); 
	printf("MAC addr source: ");
	for(i=0;i<6;i++){printf("%02x",ethernetHeader->ether_shost[i]);if(i!=5)printf(":"); else printf("\n");}
	printf("MAC adress destination: ");
	for(i=0;i<6;i++){printf("%02x",ethernetHeader->ether_dhost[i]);if(i!=5)printf(":"); else printf("\n");}
    if(ntohs(ethernetHeader->ether_type) == ETHERTYPE_PUP)//pup
    {
        printf("Ethernet type: PUP\n");
    }
    if(ntohs(ethernetHeader->ether_type) == ETHERTYPE_ARP)//ARP
    {
        printf("Ethernet type: ARP\n");
    }
    if(ntohs(ethernetHeader->ether_type) == ETHERTYPE_TRAIL)//TRAIL
    {
        printf("Ethernet type: TRAIL\n");
    }
    if(ntohs(ethernetHeader->ether_type) == ETHERTYPE_NTRAILER)//NTRAILER
    {
        printf("Ethernet type: NTRAILER\n");
    }
	if(ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP)//IP
	{
		printf("Ethernet type: IP\n");
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
		printf("source IP addr:%s\n",inet_ntoa(ipHeader->ip_src));
		printf("desitnation IP addr:%s\n",inet_ntoa(ipHeader->ip_dst));
        if(ipHeader->ip_p==6||ipHeader->ip_p==17)
        {
		if(ipHeader->ip_p==6)printf("Protocol: TCP\n");
		else if(ipHeader->ip_p==17)printf("Protocol: UDP\n");

        tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
		printf("source port: %d\n",ntohs(tcpHeader->th_sport));
		printf("desitnation port: %d\n",ntohs(tcpHeader->th_dport));
        printf("Sequence Number:%u\n",ntohl(tcpHeader->th_seq));
        printf("Acknowledgment Number:%u\n",ntohl(tcpHeader->th_ack));
        
        }
		
	}

	printf("--------------------------------------\n");
}

int main(int argc ,char *argv[])
{
	//printf("argc=%d\n",argc);
	char err[PCAP_ERRBUF_SIZE], * device,filename[100];
	//set pcap device
	device = pcap_lookupdev(err);
	if(!device)
	{
		    fprintf(stderr, "pcap_lookupdev(): %s\n", err);
			    exit(1);
	}

	//open pcap interface 65535->get65535byte/pack  1->promiscous Mode 1->in pcap loop deal with pack for every (1)ms
	strcpy(filename,"saved.pcap");
	pcap_t *handle = pcap_open_offline(filename, err);
    if(argc>1){ handle=pcap_open_live(device, 65535, 1, 0, err);printf("online capturing\n");}
	if(!handle) 
	{
			fprintf(stderr, "pcap_open_offline(): %s\n", err);
			exit(1);
	}
	printf("Open: %s\n", filename);

	pcap_loop(handle, -1, getPacket, NULL);
	pcap_close(handle);

	return 0;
}
