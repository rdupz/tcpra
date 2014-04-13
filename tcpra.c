/***** Fichier: tcpra.c *****/
/** TCP Reordering Analysis **/
/** Un outil pour analyser les problemes d'ordre d'arrivee des paquets TCP **/

#include "tcpra.h"

/* Verifie que l'extension de filename est bien .pcap */
int verify_pcap( const char *filename )
{
      char *p = strrchr(filename,'.');
      if ( p != NULL)
	    return ( strcmp(++p, "pcap") == 0 );
      return 0;
}


/* Si filename est "dir/cap.pcap", cree (ou ecrase) "dir/cap.csv" */
FILE *create_csv_file( const char *filename )
{
      FILE *csv;
      char *csv_file_name = malloc(strlen(filename)+1);
      strcpy(csv_file_name, filename);
      char *p = strrchr(csv_file_name,'.' );
      if ( p == NULL) 
      {
	    perror("create csv file");
      }
      strcpy(p, ".csv");
      csv = fopen(csv_file_name, "w+");
      if (csv == NULL)
      {
	    perror("create csv file");
      }
      free(csv_file_name);
      return csv;
}

/* Si filename est "dir/cap.pcap", cree (ou ecrase) "dir/cap.lost" */
FILE *create_lost_file( const char *filename, int maxlate )
{
      FILE *lost;
      char *lost_file_name = malloc(strlen(filename)+2);
      strcpy(lost_file_name, filename);
      char *p = strrchr(lost_file_name,'.' );
      if ( p == NULL) 
      {
	    perror("create lost file");
      }
      strcpy(p, ".lost");
      lost = fopen(lost_file_name, "w+");
      if (lost == NULL)
      {
	    perror("create lost file");
      }
      free(lost_file_name);
      fprintf(lost, "Liste des paquets qui ont un retard superieur a %d\n", maxlate);
      return lost;
}

/* Verifie la presence de la couche ip ainsi que sa nature (v4 ou v6) */
int ip_after_mac( const u_char *packet )
{
      struct ether_header *header = (struct ether_header *)packet;
      if ( header->ether_type == ntohs(ETHERTYPE_IP) )
	    return 1;
      if ( header->ether_type == ntohs(ETHERTYPE_IPV6) )
	    return 2;
      return 0;
}

/* Verifie que le destinataire de packet est bien ipdaddr */
int verify_daddr( const u_char *packet, const wanted_ip *ipdaddr )
{
      switch (ip_after_mac(packet))
      {
      case 1:
	    if (ipdaddr->t_ip != IPV4) break;
	    return ( get_ipdaddr(packet) == ipdaddr->w_ip.ipv4 );
      case 2:
	    if (ipdaddr->t_ip != IPV6) break;
	    return ( get_ip6daddr(packet) == ipdaddr->w_ip.ipv6 );
      default:
	    return 0;
      }
      return 0;
}

/* Donne l'ip du destinataire du paquet (ipv4) */ 
u_int32_t get_ipdaddr( const u_char *packet )
{
      struct iphdr *header = (struct iphdr *)(packet + ETHER_HDR_LEN);
      return header->daddr;
}

/* Donne l'ip du destinataire du paquet (ipv6) */
uint8_t *get_ip6daddr( const u_char *packet )
{
      struct ip6_hdr *header = (struct ip6_hdr *)(packet + ETHER_HDR_LEN);
      return header->ip6_dst.s6_addr;
}

/*  Si le packet est un SYN-ACK, remplit ipdaddr avec l'ip de destination du packet 
 *  et retourne vrai.
 *  Sinon retourne faux
 */
int fix_ipdaddr( const u_char *packet, wanted_ip *ipdaddr )
{
      struct tcphdr *tcphdr = get_tcphdr(packet);
      if ( (tcphdr->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK) )
      {
	    switch(ip_after_mac(packet))
	    {
	    case 1:
		  ipdaddr->t_ip = IPV4;
		  ipdaddr->w_ip.ipv4 = get_ipdaddr(packet);
		  return 1;
	    case 2:
		  ipdaddr->t_ip = IPV6;
		  ipdaddr->w_ip.ipv6 = get_ip6daddr(packet);
		  return 1;
	    default:
		  return 0;
	    }
	    
      }
      return 0;
}

/* Verifie la presence de l'entete tcp apres l'entete ipv4 */
int tcp_after_ip( const u_char *packet )
{
      struct iphdr *header = (struct iphdr *)(packet + ETHER_HDR_LEN);
      return ( header->protocol == 0x06 );

}

/* Verifie la presence de l'entete tcp apres l'entete ipv6 */
int tcp_after_ipv6( const u_char *packet )
{
      struct ip6_hdr *header = (struct ip6_hdr *)(packet + ETHER_HDR_LEN);
      return ( header->ip6_nxt == 0x06 );

}

/* Retourne la taille en octets de ce que suit l'entete ipv6 du packet */
uint16_t get_ip6_plen( const u_char *packet )
{
      struct ip6_hdr *header = (struct ip6_hdr *)(packet + ETHER_HDR_LEN);
      return header->ip6_plen;
}

/* Retourne la taille en octets de ce que suit l'entete ipv4 du packet */
uint16_t get_ip_plen( const u_char *packet )
{
      struct iphdr *header = (struct iphdr *)(packet + ETHER_HDR_LEN);
      return (ntohs(header->tot_len) - 4*(header->ihl));
} 

/* Verifie que les couches mac,ipv4 ou ipV6, et tcp se succede dans packet
 * et rend 1 si le packet est ipv4, 2 si il est ipv6.
 */
int valid_packet( const u_char *packet )
{
      switch (ip_after_mac(packet))
      {
      case 1:
	    if (tcp_after_ip(packet)) return 1;
      case 2:
	    if (tcp_after_ipv6(packet)) return 2;
      default:
	    return 0;
      }
}

/* Rend un pointeur sur l'entete tcp de packet s'il est valide, NULL sinon  */
struct tcphdr *get_tcphdr( const u_char *packet )
{
      size_t ip_hdr = 0;
      int valid = valid_packet(packet);

      if (!valid) 
	    return NULL;
      if (valid == 1)
	    ip_hdr = IP_HDR_LEN;
      if (valid == 2)
	    ip_hdr = IP6_HDR_LEN;
	    
      return (struct tcphdr *)(packet + (ETHER_HDR_LEN + ip_hdr));
      
}

/* Rend le numero de sequence de l'entete tcp header */
long get_sequence_number( const struct tcphdr *header )
{
      return htonl(header->th_seq);
}

/* tcph doit etre le header tcp de packet 
 * Rend la taille du payload tcp en octet  
 */
int get_payload_lgt( const u_char *packet , const struct tcphdr *tcph )
{
      u_int8_t offset = tcph->th_off * 4;      
      u_int16_t plen;

      switch (ip_after_mac(packet))
      {
      case 1:
	    plen = get_ip_plen(packet);
	    break;
      case 2:
	    plen = htons(get_ip6_plen(packet));
	    break;
      default:
	    return -1;
      }
      return (plen - offset);
}

/* tcph doit etre le header tcp de packet 
 * Rend la sequence attendue du paquet qui suit packet.
 */
long get_next_sequence_number( const u_char *packet , const struct tcphdr *tcph )
{
      return get_sequence_number(tcph)+ get_payload_lgt( packet, tcph);
}

/* initialise la liste dynamique */
packet_late *init_late()
{
      packet_late *begin = malloc(sizeof(packet_late));
      begin->p_sequence = 0;
      begin->expected = 0;
      begin->next = NULL;

      return begin;
}

/* Insere un element dans la liste list*/
packet_late *save_packet( packet_late *list, long p_sequence, long expected )
{     
      packet_late *new = malloc(sizeof(packet_late));
      list->next = new;
      new->p_sequence = p_sequence;
      new->expected = expected; 
      new->next = NULL;
      return list->next;
}

/*
 * Recherche a partir de packet, le paquet qui a pour sequence seq.
 * Si le retard est inferieur a maxlate et non nul, on reporte le retard du paquet dans le csv.
 * Si writelost est vrai et qu'on considere le paquet comme perdu, on reporte la perte dans lost.
 * La fonction retourne la séquence attendue apres le paquet comportant la séquence seq.
 * Si le paquet est considere comme perdu, on renvoit 0.
 */
long search( packet_late *packet, long seq, int maxlate, FILE *csv, FILE *lost, int writelost )
{
      int late;
      packet_late *tmp;
      long ret;
      for ( late = 0;
	    packet->next != NULL
		  && (packet->next->p_sequence != seq 
		      || late > maxlate);
	    packet = packet->next)
      {
	    ++late;
      }

      if (packet->next == NULL || late > maxlate){
	    if (writelost)
		  fprintf(lost, "%ld\n", seq);
	    return 0;
      }

      tmp = packet->next;
      ret = packet->next->expected;
      packet->next = packet->next->next;
      free(tmp);
      
      if ( late > 0 )
      {
	    fprintf(csv, "%ld, %d\n", seq, late);
      }
      return ret;
}

/* Supprime le paquet identifié par seq en debut de la liste begin */
int free_first( packet_late *begin, long seq )
{
      packet_late *tmp;
      for( ;
	   begin->next != NULL && begin->next->p_sequence != seq;
	   begin = begin->next);

      if (begin->next == NULL)
	    return -1;

      tmp = begin->next;
      begin->next = begin->next->next;
      free(tmp);
      return 0;

}

/* Supprime la liste begin */
int free_all_packet_late( packet_late *begin )
{
      packet_late *tmp;

      if (begin == NULL)
	    return 1;

      while ( begin->next != NULL )
      {
	    tmp = begin;
	    begin = begin->next;
	    free(tmp);
      }
      free(begin);
      if ( begin != NULL ){
	    return -1;
      }
      return 1;
}
