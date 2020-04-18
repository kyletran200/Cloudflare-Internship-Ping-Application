#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h> 
#include <netinet/ip_icmp.h>
#include <time.h>
#include <signal.h>
#include <string.h>

#define DEFAULT_PACKET_SIZE 56
#define DEFAULT_TTL 54
#define RECV_TIMEOUT 1

int ping_flag = 1;


void interrupt_handler(int x) {
    ping_flag = 0;
}


unsigned short checksum(void *b, int len) 
{   unsigned short *buf = b; 
    unsigned int sum=0; 
    unsigned short result; 
  
    for ( sum = 0; len > 1; len -= 2 ) 
        sum += *buf++; 
    if ( len == 1 ) 
        sum += *(unsigned char*)buf; 
    sum = (sum >> 16) + (sum & 0xFFFF); 
    sum += (sum >> 16); 
    result = ~sum; 
    return result; 
} 

void ping(int sock_fd, struct sockaddr_in *sa_dest, char* ip_addr) 
{
    int ttl = DEFAULT_TTL;
    int seq = 0;
    int packets_recieved = 0;

    struct icmp icmp_hdr;
    struct sockaddr_in sa_from;
    struct timespec start_time, end_time;
    struct timeval tv_out;
    tv_out.tv_sec = RECV_TIMEOUT;
    tv_out.tv_usec = 0;
    long double rtt = 0;


    // SOL_SOCKET ?
    if (setsockopt(sock_fd, SOL_SOCKET, IP_TTL,
                    &ttl, sizeof(ttl)) != 0)
    {
        printf("Error with setsockopt\n");
    }

    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO,
                    (const char*)&tv_out, sizeof(tv_out)))
    {
        printf("Error with setsockopt setting timeout\n");
    }
    
    while (ping_flag) {
        memset(&icmp_hdr, 0, sizeof(icmp_hdr));
        icmp_hdr.icmp_type = ICMP_ECHO;
        icmp_hdr.icmp_hun.ih_idseq.icd_id = getpid();
        icmp_hdr.icmp_hun.ih_idseq.icd_seq = seq;
        icmp_hdr.icmp_cksum = checksum(&icmp_hdr, sizeof(icmp_hdr));


        usleep(1000000);

        clock_gettime(CLOCK_MONOTONIC, &start_time);
        if (sendto(sock_fd, &icmp_hdr, sizeof(icmp_hdr), 0, (struct sockaddr*)sa_dest, sizeof(*sa_dest)) <= 0) 
        {
            printf("Error with sendto\n");
            return;
        }

        socklen_t addr_len = sizeof(sa_from);

        if (recvfrom(sock_fd, &icmp_hdr, sizeof(icmp_hdr), 0, (struct sockaddr*)&sa_from, &addr_len) <= 0)
        {
            printf("Error with recvfrom\n");
            return;
        }
            
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        double timeElapsed = ((double)(end_time.tv_nsec -  start_time.tv_nsec))/1000000.0;
        rtt = (end_time.tv_sec-start_time.tv_sec) * 1000.0 + timeElapsed;
        printf("%d %s %s:", 64, "bytes from", ip_addr); // Report bytes and IP address
        printf("%s=%d", " icmp_seq", seq);                // Report icmp_seq
        printf("%s=%d", " ttl", DEFAULT_TTL);                                        // Report TTL
        printf("%s %.3Lf %s\n", " rtt =", rtt, "ms"); // Report RTT
        packets_recieved++;     //Increment packet recieved
        seq ++;
    }

    printf("--- ping statistics ---\n");
    double packet_loss = 100.0 * ((seq - packets_recieved)/(seq));
    printf("%d packets transmitted, %d packets recieved, %.1f",
            seq, packets_recieved, packet_loss);
    printf("%% packet loss\n");
    

} 

int main(int argc, char ** argv) 
{
    /* Our ping app should only accept 1 argument */
    if (argc != 2) {
        printf("Error incorrect usage\n");
        return 1;
    }

    //char* input = argv[1];

    //char host_cstr[input.size()+1];
    //strcpy(host_cstr, input.c_str());

    int status;
    struct addrinfo hints;
    struct addrinfo *res;
    char ipstr[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    //hints.ai_flags = AI_PASSIVE;

    if ((status = getaddrinfo(argv[1], NULL, &hints, &res)) != 0) {
        printf("Error with getaddrinfo\n");
        return 2;
    }

    struct addrinfo *p;
    struct sockaddr_in sockaddr_dest_ipv4;
    struct sockaddr_in6 sockaddr_dest_ipv6;

    for (p = res;p != NULL; p = p->ai_next) {
        void *addr;
        char* ipver;
        // get the pointer to the address itself,
        // different fields in IPv4 and IPv6:
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
            sockaddr_dest_ipv4 = *ipv4;
        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
            sockaddr_dest_ipv6 = *ipv6;
        }
        // convert the IP to a string and print it:
        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        printf("  %s: %s\n", ipver, ipstr);

    }

    //print_vector(ipv6_addrs);
    //print_vector(ipv4_addrs);

    // ------------------ It's socket time!  ------------------------- //

    int sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sockfd < 0) {
        printf("Error with socket\n");
        return 1;
    }


    char ip_addr[INET6_ADDRSTRLEN];
    void *sa_sinaddr = &(sockaddr_dest_ipv4.sin_addr);
    inet_ntop(AF_INET, sa_sinaddr, ip_addr, sizeof ip_addr);
    printf("%s %s (%s): %d %s", "PING", argv[1], ip_addr, DEFAULT_PACKET_SIZE, "data bytes\n");


    signal(SIGINT, interrupt_handler);
    ping(sockfd, &sockaddr_dest_ipv4, ip_addr); 


    freeaddrinfo(res);
    return 0;
}   
