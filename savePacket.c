#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

void pcap_callback(u_char * dumper, const struct pcap_pkthdr * header, const u_char * content)
{
	static int d = 0;
	printf("\rNo.%d captured\n", ++d);
	//dump to file
	pcap_dump(dumper, header, content);
}

int main()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device = NULL;
	int n;
	 printf("enter num of captured pack\n");
	 scanf("%d",&n);
	 printf("\n\n");
	//set pcap device
	device = pcap_lookupdev(errbuf);
	if(!device)
	{
		    fprintf(stderr, "pcap_lookupdev(): %s\n", errbuf);
			    exit(1);
	}
	 
	////open pcap interface 65535->get65535byte/pack  1->promiscous Mode 1->in pcap loop deal with pack for every (1)ms
	pcap_t *handle = pcap_open_live(device, 65535, 1, 1, errbuf);
	if(!handle)
	{
		    fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
			    exit(1);
	}

	//open file handler
	const char *filename = "saved.pcap";
	pcap_dumper_t *dumper = pcap_dump_open(handle, filename);
	if(!dumper)
	{
		    fprintf(stderr, "pcap_dump_open(): %s\n", pcap_geterr(handle));
			    pcap_close(handle);
				    exit(1);
	}

	printf("Saving to %s\n", filename);
	
	//start capture loop
	if(0 != pcap_loop(handle, n, pcap_callback, (u_char *)dumper)) {
		    fprintf(stderr, "pcap_loop(): %s\n", pcap_geterr(handle));
	}
	//flush and close
	pcap_dump_flush(dumper);
	pcap_dump_close(dumper);
	printf("\nDone\n");
	//free
	pcap_close(handle);
	return 0;
}
