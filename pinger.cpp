#include <iostream>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h> 
#include <string>
#include <cstring>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <signal.h>
#include <vector>

#define DEFAULT_PACKET_SIZE 56
#define DEFAULT_TTL 64
#define RECV_TIMEOUT 1

using namespace std;

int ping_flag = 1;


void interrupt_handler(int x) {
    ping_flag = 0;
}

void print_vector(vector<string> v) {
    for (int i = 0; i < v.size(); i++) {
        cout << v[i] << " ";
    }
    cout << "\n";
}

char* hostname_to_ip(string addr_host) 
{
    cout << "Resolving DNS..." << endl;
    struct hostent *host_entity;

    char host_cstr[addr_host.size()+1];
    char *ip_address = (char*)malloc(NI_MAXHOST*sizeof(char));

    strcpy(host_cstr, addr_host.c_str());
    host_entity = gethostbyname(host_cstr); 

    if (host_entity == NULL) {
        cerr << "No IP address found." << endl;
        return NULL;
    }

    /* Important Line */
    strcpy(ip_address, inet_ntoa(*(struct in_addr *)host_entity->h_addr));
    return ip_address;
}


void ping(int sock_fd, struct sockaddr_in *ping_addr, char *ping_ip) 
{
    int ttl = DEFAULT_TTL;
    int seq = 0;

    struct icmphdr icmp_hdr;
    struct sockaddr_in addr;
    struct timespec start_time, end_time;
    struct timeval tv_out;
    tv_out.tv_sec = RECV_TIMEOUT;
    tv_out.tv_usec = 0;

    clock_gettime(CLOCK_MONOTONIC, &start_time);

    /*
    if (setsockopt(sock_fd, SOL_IP, IP_TTL,
                    &ttl, sizeof(ttl)) != 0)
    {
        cerr << "Error setting socket option to TTL" << endl;
        return 1;
    }

    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO,
                    (const char*)&tv_out, sizeof(tv_out)))
    {
        cerr << "Error setting timeout of recv setting " << endl;
        return 1;
    }
    */
    
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    long seconds = end_time.tv_sec - start_time.tv_sec;
    long ns = end_time.tv_sec - start_time.tv_sec;

    if (start_time.tv_nsec > end_time.tv_nsec) { 
        --seconds; 
        ns += 1000000000; 
    } 

    cout << (double)seconds + (double)ns/(double)1000000000 << endl;
} 

int main(int argc, char ** argv) 
{
    /* Our ping app should only accept 1 argument */
    if (argc != 2) {
        cerr << "usage: " << argv[0] << " <hostname> or <ip address>" << endl;
        return 1;
    }

    string input = argv[1];
    cout << "This is input: " << input << endl;

    char host_cstr[input.size()+1];
    strcpy(host_cstr, input.c_str());

    int status;
    struct addrinfo hints;
    struct addrinfo *res;
    char ipstr[INET6_ADDRSTRLEN];

    vector<string> ipv4_addrs;
    vector<string> ipv6_addrs;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    //hints.ai_flags = AI_PASSIVE;

    if ((status = getaddrinfo(host_cstr, NULL, &hints, &res)) != 0) {
        cerr << "Error with getaddrinfo" << endl;
        return 2;
    }

    struct addrinfo *p;
    for(p = res;p != NULL; p = p->ai_next) {
        void *addr;
        string ipver;
        // get the pointer to the address itself,
        // different fields in IPv4 and IPv6:
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }
        // convert the IP to a string and print it:
        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        cout << ipver << ": " << ipstr << endl;

        if (ipver == "IPv6") {
            ipv6_addrs.push_back(string(ipstr));
        }
        else {
            ipv4_addrs.push_back(string(ipstr));
        }
    }

    //print_vector(ipv6_addrs);
    //print_vector(ipv4_addrs);

    /* Obtaining IP address using gethostname
    char *ip_address;
    ip_address = hostname_to_ip(input);

    if (ip_address == NULL) {
        cerr << "DNS lookup failed" << endl;
        return 1;
    }

    wcout << ip_address << endl; */

    // ------------------ It's socket time!  ------------------------- //

    int packet_size = DEFAULT_PACKET_SIZE;
    int ttl = DEFAULT_TTL;
    int sock_domain = PF_INET;
    struct sockaddr_in sa;

    char ip_address[ipv4_addrs[0].size()+1];
    strcpy(host_cstr, ipv4_addrs[0].c_str());

    //SOCK_DGRAM or SOCK_RAW?
    int sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        cerr << "Error with socket" << endl;
        return 1;
    }


    signal(SIGINT, interrupt_handler);
    ping(sockfd, &sa, ip_address); 


    freeaddrinfo(res);
    return 0;
}   
