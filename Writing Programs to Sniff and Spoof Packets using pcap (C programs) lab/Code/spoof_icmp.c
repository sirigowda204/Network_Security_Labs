#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdlib.h>

/* ICMP Header */
struct icmpheader
{
    unsigned char icmp_type;        // ICMP me s sage type
    unsigned char icmp_code;        // Erro r code
    unsigned short int icmp_chksum; //Checksum for ICMP Header and data
    unsigned short int icmp_id;     //Used for ide ntifying request
    unsigned short int icmp_seq;    //Sequence number
};

struct ipheader
{

    unsigned char iph_ihl : 4, iph_ver : 4;           //IP header length, //IP version
    unsigned char iph_tos;                            //Type of service
    unsigned short int iph_len;                       //IP Packet length (data+ header )
    unsigned short int iph_ident;                     //Identification
    unsigned short int iph_flag : 3, iph_offset : 13; //Fragmentation flags //Flags offset
    unsigned char iph_ttl;                            //Time to Live
    unsigned char iph_protocol;                       //Protocol type
    unsigned short int iph_chksum;                    //IP datagram checksum
    struct in_addr iph_sourceip;                      //Source IP address
    struct in_addr iph_destip;                        //Destination IP address
};

unsigned short in_cksum(unsigned short *buf, int length);
void send_raw_ip_packet(struct ipheader *ip);

/** * ******** * ******* * * * ***** * *********** * ************************** 
Spoof an ICMP echo request using an arbitrary source IP Address 
*******************************************************************/
int main()
{
    char buffer[1500];
    memset(buffer, 0, 1500);
    /**************** * **************************************** 
    Step 1 : Fill in the ICMP header . 
    ********************************************************/
    struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
    icmp->icmp_type = 8; //ICMP Type : 8 is request , 0 is reply .
    // Calculate the checksum for integrity
    icmp->icmp_chksurn 0;
    icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
                                 sizeof(struct icmpheader));

    /********************************************************* 
    Step 2 : Fill in the IP header . 
    ********************************************************/
    struct ipheader *ip = (struct ipheader *)buffer;
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
    ip->iph_destip.s_addr = inet_addr("10.0.2.8");
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_len = htons(sizeof(struct ipheader) +
                        sizeof(struct icmpheader));
    /********************************************************* 
    Step 3 : Finally, send the spoofed packet 
    ********************************************************/
    send_raw_ip_packet(ip);
    return 0;
}

void send_raw_ip_packet(struct ipheader *ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;
    // Step 1 : Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    // Step 2 : Set socket option .
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    // Step 3 : Provide neede d informatio n a bout de stination .
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;
    // Step 4 : Send the packet out .
    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

unsigned short in_chksum(unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1)
    {
        *(u_char *)(&temp) = *(u_char *)w;
        sum += temp;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}