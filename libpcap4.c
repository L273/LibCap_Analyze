#include<stdio.h>
#include<pcap.h>
#include<stdlib.h>
#include<time.h>
void analyse(u_char *userarg,const struct pcap_pkthdr * pkthdr, const u_char * packet);
unsigned long outPut16(unsigned long temp,int i, const u_char * packet);
int main(void)
{
	char * dev;
	char errBuf[PCAP_ERRBUF_SIZE];
	pcap_t * head;
	dev="ens33";
	head = pcap_open_offline("/tmp/Libpcap4/Hospital.pcapng",errBuf);
	const u_char * pack_check;
	struct pcap_pkthdr data;
	int id=0;
	if(head)
	{
		pcap_loop(head,-1,analyse,(u_char*)(&id));
	}
	else
	{
		printf("error is %s \n",errBuf);
		exit(1);
	}
	pcap_close(head);
	return 0;
}
void analyse(u_char *userarg,const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
	int * id = (int *)userarg;  
	printf("---------------------------------------------------------------------\n");
	printf("id: %d\n", ++(*id));  
	printf("length: %d\n", pkthdr->len);  
	printf("Number of bytes: %d\n", pkthdr->caplen);  
	printf("time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));
	int i;

	//IPv4
	unsigned long type=0xffff;
	unsigned long length=0xffff;
	unsigned long ID=0xffff;
	unsigned long flags=0xffff;
	unsigned long check=0xffff;
	long protocol=0xff;
	//IPv4

	//PPPOE
	unsigned long session_ID=0xffff;
	long code=0xff;
	unsigned long length_Payload=0xffff;
	//PPPOE

	//PPP
	unsigned long protocol_ppp=0xffff;
	//PPP

	//TCP
	unsigned long source_port=0xffff;
	unsigned long destination_port=0xffff;
	unsigned long tcp_flags=0xffff;
	unsigned long windows_size=0xffff;
	unsigned long check_tcp=0xffff;
	unsigned long pointer_tcp=0xffff;
	//TCP

	//UDP
	unsigned long source_port_udp=0xffff;
	unsigned long destination_port_udp=0xffff;
	unsigned long length_udp=0xffff;
	unsigned long checksum_udp=0xffff;
	//UDP

	//TS file
	FILE *fp;
	//TS file
	
	printf("---------------------------------------------------\n");
	printf("---------------Ethernet II-------------------------\n");
	printf("Destination MAC is  ");
	for(i=0; i<6; ++i)
	{
		printf(": %02x", packet[i]); 
	}
	printf("\nSource MAC is       ");
	for(;i<12; ++i)
	{
		printf(": %02x", packet[i]); 
	}
	printf("\n");
	type=outPut16(type,i,packet);
	i+=2;//14
	if(type==0x8864) 
	{
		printf("Protocol is PPPOE   :");
	}
	else if(type==0x0800)
	{
		printf("Protocol is IPv4    :");
	}
	else if(type==0x0806)
	{
		printf("Protocol is ARP     :");
	}
	else if(type==0x8847 || type==0x8848)
	{
		printf("Protocol is MPLS    :");
	}
	else if(type==0x8137)
	{
		printf("Protocol is IS-IS   :");
	}
	else if(type==0x8000)
	{
		printf("Protocol is LACP    :");
	}
	else if(type==0x8809)
	{
		printf("Protocol is 802.1x  :");
	}
	else
	{
		printf("Don't know          :");
	}
	printf(" type=0x%04x\n",type);

	if(type==0x8864)
	{
		printf("---------------------------------------------------\n");
		printf("-----------------PPPOE-----------------------------\n");
		printf("Version is          :");
		printf(" %d\n",packet[i]&0xf0/16);
		printf("Type is             :");
		printf(" %d\n",packet[i]&0x0f);	
		i++;//15
		printf("Code is             :");
		code=packet[i];
		if(packet[i]==0x00)
		{
			printf(" Session Data(0x00)\n");
		}
		else if(packet[i]==0x09)
		{
			printf(" PADI Data(0x09)\n");
		}
		else if(packet[i]==0x07)
		{
			printf(" PADO or PADT Data(0x09)\n");
		}
		else if(packet[i]==0x19)
		{
			printf(" PADR Data(0x09)\n");
		}
		else if(packet[i]==0x65)
		{
			printf(" PADS Data(0x09)\n");
		}
		i++;//16
		session_ID=outPut16(session_ID,i,packet);
		i+=2;//18
		printf("Session ID is        :");
		printf(" 0x%04x\n",session_ID);
		length_Payload=outPut16(length_Payload,i,packet);
		i+=2;//20
		printf("Payload Length is    :");
		printf(" %ld\n",length_Payload);
		if(code==0x00)
		{
			printf("---------------------------------------------------\n");
			printf("------------------PPP------------------------------\n");
			protocol_ppp=outPut16(protocol_ppp,i,packet);
			i+=2;//22
			printf("Protocol is          :");
			if(protocol_ppp=0x0021)
			{
				printf(" IPv4 (0x%04x)\n",protocol_ppp);
			}		
			else if(protocol_ppp=0xC021)
			{
				printf(" LCP (0x%04x)\n",protocol_ppp);
			}
			else if(protocol_ppp=0x8021)
			{
				printf(" NCP (0x%04x)\n",protocol_ppp);
			}
			else if(protocol_ppp=0xC023)
			{
				printf(" PAP (0x%04x)\n",protocol_ppp);
			}
			else if(protocol_ppp=0xC025)
			{
				printf(" LQR (0x%04x)\n",protocol_ppp);
			}
			else if(protocol_ppp=0xC22e)
			{
				printf(" CHAP (0x%04x)\n",protocol_ppp);
			}
		}
		if(protocol_ppp==0x0021)
		{
			printf("---------------------------------------------------\n");
			printf("------------------IPv4-----------------------------\n");
			printf("IP Version is       :");
			printf(" %d\n",(packet[i]&0xf0)/16);
			printf("Header Length is    :");
			printf(" %d bytes\n",(packet[i]&0x0f)*4);
			i++;//23
			printf("Type Of Service is  :");
			printf(" 0x%02x\n",packet[i]);
			printf("	Max delay is    : %d\n",packet[i]/32%2);
			printf("	Max thruput is  : %d\n",packet[i]/16%2);
			printf("	Max reliable is : %d\n",packet[i]/8%2);
			printf("	Min cost is     : %d\n",packet[i]/4%2);
			i++;//24
			length=outPut16(length,i,packet);
			i+=2;//26
			printf("Total length is     :");
			printf(" %d bytes \n",length);
			ID=outPut16(ID,i,packet);
			i+=2;//28
			printf("Indetification is   :");
			printf(" 0x%04x\n",ID);
			flags=outPut16(flags,i,packet);
			i+=2;//30
			printf("Flag is             :");
			printf(" 0x%04x\n",flags);
			printf("	Resverved bit is : %d\n",flags/128/128);
			printf("	Don't fragment is: %d\n",flags/128/64%2);
			printf("	More fragments is: %d\n",flags/128/32%2);
			printf("Fragment offset is  :");
			printf(" %d\n",flags&0x1fff);
			printf("Time to Live is     :");
			printf(" %d\n",packet[i]);
			i++;//31
			printf("Protocol is         :");
			if(packet[i]==0x01) 
			{
				protocol=packet[i];
				printf(" ICMP\n");
			}
			else if(packet[i]==0x06)
			{
				protocol=packet[i];
				printf(" TCP\n");
			}
			else if(packet[i]==0x11)
			{
				protocol=packet[i];
				printf(" UDP\n");
			}
			else
			{
				protocol=packet[i];
				printf(" Don't know\n");
			}
			i++;//32
			check=outPut16(check,i,packet);
			i++;//34
			printf("Header checksum is  :");
			printf(" 0x%04x\n",check);
			i++;//35
			printf("Source IP is        :");
			printf(" %d.%d.%d.%d\n",packet[i],packet[i+1],packet[i+2],packet[i+3]);
			i+=4;//39
			printf("Destination IP is   :");
			printf(" %d.%d.%d.%d\n",packet[i],packet[i+1],packet[i+2],packet[i+3]);
			i+=4;//43
			}
	}
	else if(type==0x0800)
	{
		printf("---------------------------------------------------\n");
		printf("------------------IPv4-----------------------------\n");
		printf("IP Version is       :");
		printf(" %d\n",(packet[i]&0xf0)/16);
		printf("Header Length is    :");
		printf(" %d bytes\n",(packet[i]&0x0f)*4);
		i++;//15
		printf("Type Of Service is  :");
		printf(" 0x%02x\n",packet[i]);
		printf("	Max delay is    : %d\n",packet[i]/32%2);
		printf("	Max thruput is  : %d\n",packet[i]/16%2);
		printf("	Max reliable is : %d\n",packet[i]/8%2);
		printf("	Min cost is     : %d\n",packet[i]/4%2);
		i++;//16
		length=outPut16(length,i,packet);
		i+=2;//18
		printf("Total length is     :");
		printf(" %d bytes \n",length);
		ID=outPut16(ID,i,packet);
		i+=2;//20
		printf("Indetification is   :");
		printf(" 0x%04x\n",ID);
		flags=outPut16(flags,i,packet);
		i+=2;//22
		printf("Flag is             :");
		printf(" 0x%04x\n",flags);
		printf("	Resverved bit is : %d\n",flags/128/128);
		printf("	Don't fragment is: %d\n",flags/128/64%2);
		printf("	More fragments is: %d\n",flags/128/32%2);
		printf("Fragment offset is  :");
		printf(" %d\n",flags&0x1fff);
		printf("Time to Live is     :");
		printf(" %d\n",packet[i]);
		i++;//23
		printf("Protocol is         :");
		if(packet[i]==0x01) 
		{
			protocol=packet[i];
			printf(" ICMP\n");
		}
		else if(packet[i]==0x06)
		{
			protocol=packet[i];
			printf(" TCP\n");
		}
		else if(packet[i]==0x11)
		{
			protocol=packet[i];
			printf(" UDP\n");
		}
		else
		{
			protocol=packet[i];
			printf(" Don't know\n");
		}
		i++;//24
		check=outPut16(check,i,packet);
		i++;//26
		printf("Header checksum is  :");
		printf(" 0x%04x\n",check);
		i++;//27
		printf("Source IP is        :");
		printf(" %d.%d.%d.%d\n",packet[i],packet[i+1],packet[i+2],packet[i+3]);
		i+=4;//31
		printf("Destination IP is   :");
		printf(" %d.%d.%d.%d\n",packet[i],packet[i+1],packet[i+2],packet[i+3]);
		i+=4;//35
	}
	if(protocol==0x06)
	{
		//TCP
		printf("---------------------------------------------------\n");
		printf("------------------TCP------------------------------\n");
		source_port=outPut16(source_port,i,packet);
		i+=2;//37
		printf("Source Port is      :");
		printf(" %ld\n",source_port);
		destination_port=outPut16(destination_port,i,packet);
		i+=2;//39
		printf("Destination Port is :");
		printf(" %ld\n",destination_port);
		printf("Sequence Number is  :");
		printf(" 0x%02x%02x%02x%02x (Not relative seq)\n",packet[i],packet[i+1],packet[i+2],packet[i+3]);
		i+=4;//43
		printf("Ack Number is       :");
		printf(" 0x%02x%02x%02x%02x (Not relatve ack)\n",packet[i],packet[i+1],packet[i+2],packet[i+3]);
		i+=4;//47
		tcp_flags=outPut16(tcp_flags,i,packet);
		i+=2;//49
		printf("Header Lenghth is   :");
		printf(" %d bytes\n",(tcp_flags/256/16)*4);
		printf("Reservered is       :");
		printf(" %d (Decimal Base)\n",(0x0fff&tcp_flags)/16/4);
		printf("Tcp Flags is        :");
		printf(" %d (Decimal Base)\n",0x003f&tcp_flags);
		printf("	URG is          :");
		printf(" %d\n",(0x003f&tcp_flags)/32);
		printf("	PSH is          :");
		printf(" %d\n",(0x003f&tcp_flags)/16%2);
		printf("	PST is          :");
		printf(" %d\n",(0x003f&tcp_flags)/8%2);
		printf("	FIN is          :");
		printf(" %d\n",(0x003f&tcp_flags)/4%2);
		printf("	SYN is          :");
		printf(" %d\n",(0x003f&tcp_flags)/2%2);
		printf("	ACK is          :");
		printf(" %d\n",(0x003f&tcp_flags)%2);
		windows_size=outPut16(windows_size,i,packet);
		i+=2;//51
		printf("Windows Size is      :");
		printf(" %ld bytes \n",windows_size);
		check_tcp=outPut16(check_tcp,i,packet);
		i+=2;//53
		printf("Check Summary is     :");
		printf(" %ld (Decimal Base)\n",check_tcp);
		pointer_tcp=outPut16(pointer_tcp,i,packet);
		i+=2;//55
		printf("Urgent pointer       :");
		printf(" 0x%04x\n",pointer_tcp);
	}
	else if(protocol==0x11 )
	{
		printf("---------------------------------------------------\n");
		printf("------------------UDP------------------------------\n");
		source_port_udp=outPut16(source_port_udp,i,packet);
		i+=2;
		printf("Source Port is       :");
		printf(" %ld\n",source_port_udp);
		destination_port_udp=outPut16(destination_port_udp,i,packet);
		i+=2;
		printf("Destination Port is  :");
		printf(" %ld\n",destination_port_udp);
		length_udp=outPut16(length_udp,i,packet);
		i+=2;
		printf("Length is            :");
		printf(" %ld\n",length_udp);
		checksum_udp=outPut16(checksum_udp,i,packet);
		i+=2;
		printf("Checksum   is       :");	
		printf(" %04x\n",checksum_udp);
		if(packet[i]==0x80)
		{
			i+=12;
		}
		if(type==0x8864&&packet[i]==0x47)
		{
			printf("---------------------------------------------------\n");
			printf("------------------ALL Ts Bits----------------------\n");
			fp=fopen("/tmp/Libpcap4/Hospital.ts","a+");
			for(; i<pkthdr->len; ++i)  
			{  
				printf(" %02x", packet[i]);
				fwrite(&(packet[i]),1,1,fp);
					if( (i + 1) % 16 == 0 )  
					{  
					    printf("\n");  
					}  
			}
			printf("\n");
			fclose(fp);
		}
		else if(packet[i]==0x47)
		{
			printf("---------------------------------------------------\n");
			printf("------------------ALL Ts Bits----------------------\n");
			for(; i<pkthdr->len; ++i)  
			{  
				printf(" %02x", packet[i]);
					if( (i + 1) % 16 == 0 )  
					{  
					    printf("\n");  
					}  
			}
			printf("\n");
		}
	}


	printf("---------------------------------------------------\n");
	printf("----------------ALL Bits---------------------------\n");
	for(i=0; i<pkthdr->len; ++i)  
	{  
		printf(" %02x", packet[i]);  
			if( (i + 1) % 16 == 0 )  
			{  
			    printf("\n");  
			}  
	}
	printf("\n");
	printf("---------------------------------------------------------------------\n");  
}
unsigned long outPut16(unsigned long temp,int i, const u_char * packet)
{
	temp=temp&(256*packet[i]|0x00ff);
	i++;
	temp=temp&(packet[i]+0xff00);
	return temp;
}
