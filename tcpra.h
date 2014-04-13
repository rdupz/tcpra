/***** Fichier: tcpra.c *****/
/** TCP Reordering Analysis **/
/** Un outil pour analyser les problemes d'ordre d'arrivee des paquets TCP **/

#ifndef _TCPRA_H_
#define _TCPRA_H_


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#define IP_HDR_LEN  0x14
#define IP6_HDR_LEN 0x28
#define MAX_LATE    10000

int verify_pcap( const char * );
FILE *create_csv_file( const char * );
FILE *create_lost_file( const char *, int );

int ip_after_mac( const u_char * );
int tcp_after_ip( const u_char * );
int tcp_after_ipv6( const u_char * );

enum type_ip {IPV4, IPV6};
typedef struct wanted_ip
   {
   enum type_ip t_ip;
   union
      {
      uint8_t *ipv6;
      u_int32_t ipv4;
      } w_ip;
   } wanted_ip;

int fix_ipdaddr( const u_char *, wanted_ip *);
int verify_daddr( const u_char *, const wanted_ip * );
u_int32_t get_ipdaddr( const u_char * );
uint8_t *get_ip6daddr( const u_char * );




int valid_packet( const u_char * );
struct tcphdr *get_tcphdr( const u_char * );
int get_payload_lgt( const u_char *, const struct tcphdr *);
long get_sequence_number( const struct tcphdr * );
long get_next_sequence_number( const u_char * , const struct tcphdr * );


typedef struct packet_late
{
      long p_sequence;
      long expected;
      struct packet_late *next;
      
} packet_late;


packet_late *init_late();
packet_late* save_packet( packet_late *, long, long );
long search(packet_late*, long, int, FILE *, FILE *, int);
int free_first(packet_late *, long);
int free_all_packet_late( packet_late * );

#endif 
