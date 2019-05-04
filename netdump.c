#define RETSIGTYPE void
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef setsignal_h
#define setsignal_h

RETSIGTYPE (*setsignal(int, RETSIGTYPE (*)(int)))(int);
#endif

char cpre580f98[] = "netdump";

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p);

int packettype;

char *program_name;

enum {
	IP4,
	IP6,
	ARP,
	ICMP,
	TCP,
	DNS,
	SMTP,
	POP,
	IMAP,
	HTTP,

	TNUM
};

int pack_num[TNUM];

/* Externs */
extern void bpf_dump(const struct bpf_program *, int);

extern char *copy_argv(char **);

/* Forwards */
 void program_ending(int);

/* Length of saved portion of packet. */
int snaplen = 1500;

static pcap_t *pd;

extern int optind;
extern int opterr;
extern char *optarg;
int pflag = 0, aflag = 0;

int
main(int argc, char **argv)
{
	int cnt, op, i, done = 0;
	bpf_u_int32 localnet, netmask;
	char *cp, *cmdbuf, *device;
	struct bpf_program fcode;
	 void (*oldhandler)(int);
	u_char *pcap_userdata;
	char ebuf[PCAP_ERRBUF_SIZE];

	cnt = -1;
	device = NULL;

	memset(pack_num, 0, TNUM * sizeof(int));
	
	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	opterr = 0;
	while ((i = getopt(argc, argv, "pa")) != -1)
	{
		switch (i)
		{
		case 'p':
			pflag = 1;
		break;
		case 'a':
			aflag = 1;
		break;
		case '?':
		default:
			done = 1;
		break;
		}
		if (done) break;
	}
	if (argc > (optind)) cmdbuf = copy_argv(&argv[optind]);
		else cmdbuf = "";

	if (device == NULL) {
		device = pcap_lookupdev(ebuf);
		if (device == NULL)
			error("%s", ebuf);
	}
	pd = pcap_open_live(device, snaplen,  1, 1000, ebuf);
	if (pd == NULL)
		error("%s", ebuf);
	i = pcap_snapshot(pd);
	if (snaplen < i) {
		warning("snaplen raised from %d to %d", snaplen, i);
		snaplen = i;
	}
	if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
		localnet = 0;
		netmask = 0;
		warning("%s", ebuf);
	}
	/*
	 * Let user own process after socket has been opened.
	 */
	setuid(getuid());

	if (pcap_compile(pd, &fcode, cmdbuf, 1, netmask) < 0)
		error("%s", pcap_geterr(pd));
	
	(void)setsignal(SIGTERM, program_ending);
	(void)setsignal(SIGINT, program_ending);
	/* Cooperate with nohup(1) */
	if ((oldhandler = setsignal(SIGHUP, program_ending)) != SIG_DFL)
		(void)setsignal(SIGHUP, oldhandler);

	if (pcap_setfilter(pd, &fcode) < 0)
		error("%s", pcap_geterr(pd));
	pcap_userdata = 0;
	(void)fprintf(stderr, "%s: listening on %s\n", program_name, device);
	if (pcap_loop(pd, cnt, raw_print, pcap_userdata) < 0) {
		(void)fprintf(stderr, "%s: pcap_loop: %s\n",
		    program_name, pcap_geterr(pd));
		exit(1);
	}
	pcap_close(pd);
	exit(0);
}

/* routine is executed on exit */
void program_ending(int signo)
{
	struct pcap_stat stat;

	if (pd != NULL && pcap_file(pd) == NULL) {
		(void)fflush(stdout);
		putc('\n', stderr);
		if (pcap_stats(pd, &stat) < 0)
			(void)fprintf(stderr, "pcap_stats: %s\n",
			    pcap_geterr(pd));
		else {
			(void)fprintf(stderr, "%d packets received by filter\n",
			    stat.ps_recv);
			(void)fprintf(stderr, "%d packets dropped by kernel\n",
			    stat.ps_drop);
			(void)fprintf(stderr, "%d packets were ipv4\n", pack_num[IP4]);
			(void)fprintf(stderr, "%d packets were ipv6\n", pack_num[IP6]);
			(void)fprintf(stderr, "%d packets were ARP\n", pack_num[ARP]);
			(void)fprintf(stderr, "%d packets were ICMP\n", pack_num[ICMP]);
			(void)fprintf(stderr, "%d packets were TCP\n", pack_num[TCP]);
			(void)fprintf(stderr, "%d packets were DNS\n", pack_num[DNS]);
			(void)fprintf(stderr, "%d packets were SMTP\n", pack_num[SMTP]);
			(void)fprintf(stderr, "%d packets were POP\n", pack_num[POP]);
			(void)fprintf(stderr, "%d packets were IMAP\n", pack_num[IMAP]);
			(void)fprintf(stderr, "%d packets were HTTP\n", pack_num[HTTP]);
		}
	}
	exit(0);
}

/* Like default_print() but data need not be aligned */
void
default_print_unaligned(register const u_char *cp, register u_int length)
{
	register u_int i, s;
	register int nshorts;

	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t\t\t");
		s = *cp++;
		(void)printf(" %02x%02x", s, *cp++);
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t\t\t");
		(void)printf(" %02x", *cp);
	}
}

/*
 * By default, print the packet out in hex.
 */
void
default_print(register const u_char *bp, register u_int length)
{
	register const u_short *sp;
	register u_int i;
	register int nshorts;

	if ((long)bp & 1) {
		default_print_unaligned(bp, length);
		return;
	}
	sp = (u_short *)bp;
	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t");
		(void)printf(" %04x", ntohs(*sp++));
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t");
		(void)printf(" %02x", *(u_char *)sp);
	}
}

/*
insert your code in this routine

*/

void print_arp(const u_char *p)
{
	int i;
	int offset = 8;

	uint16_t hwtype = p[0] * 256 + p[1];
	uint16_t prototype = p[2] * 256 + p[3];
	uint8_t hwlen = p[4];
	uint8_t protolen = p[5];

	uint16_t oper = p[6] * 256 + p[7];
	
	printf("Hardware type: %u\n", hwtype);
	printf("Protocol type: %u\n", prototype);
	printf("Hardware length: %u\n", hwlen);
	printf("Protocol length: %u\n", protolen);
	printf("Operation: %d -> %s\n", oper, (oper == 1 ? "Request" : "Reply"));

	printf("Sender Hardware address: ");
	for(i=0;i<hwlen;i++)
		printf("%02X%c", p[offset+i], ( i == (hwlen-1) ? '\n' : ':'));

	offset += hwlen;
	printf("Sender Protocol address: ");
	for(i=0;i<protolen;i++)
		printf("%d%c", p[offset+i], ( i == (protolen-1) ? '\n' : '.'));

	offset+=protolen;
	printf("Target Hardware address: ");
	for(i=0;i<hwlen;i++)
		printf("%02X%c", p[offset+i], ( i == (hwlen-1) ? '\n' : ':'));

	offset += hwlen;
	printf("Target Protocol address: ");
	for(i=0;i<protolen;i++)
		printf("%d%c", p[offset+i], ( i == (protolen-1) ? '\n' : '.'));
}

void print_icmp(const u_char *p)
{
	pack_num[ICMP]++;
	uint32_t timestamp;
	int i;
	int offset = 4;
	uint8_t type = p[0];
	uint8_t code = p[1];
	uint16_t checksum = p[2] << 8 + p[3];

	printf("ICMP Header:\n");
	printf("\tType: %u\n", type);
	printf("\tCode: %u\n", code);
	printf("\tChecksum: %u\n", checksum);

	switch(type){
	case 13:
	case 14:
		for(i=0;i<4;i++){
			timestamp = *(p+offset);
			printf("\tTime stamp %d: %u\n");
			offset+=4;
		}
		break;
	}
}

void print_mail(const u_char *p)
{
	char *endline;
	while((endline = strstr(p, "\r\n")) != NULL){
		*endline = '\0';
		printf("%s\n", p);
		p = endline+1;
	}
}


void print_http(const u_char *p)
{
	char *endmsg = strstr(p, "</html>");
	if(endmsg == NULL){
		endmsg = strstr(p, "\r\n\r\n");
		if(endmsg != NULL){
			goto print;
		}
		return;
	}
	endmsg+=7;

print:
	*endmsg = '\0';
	printf("HTTP Payload:\n\n%s\n\n", p);

}

void print_tcp(const u_char *p)
{
	pack_num[TCP]++;
	uint16_t source_port = (p[0] << 8) + p[1];
	uint16_t dest_port = (p[2] << 8) + p[3];

	uint32_t seq = p[4] << 24 + p[5] << 16 + p[6] << 8 + p[7];
	uint32_t ack = p[8] << 24 + p[9] << 16 + p[10] << 8 + p[11];
	
	uint16_t temp = p[12] * 256 + p[13];
	uint8_t hdrlen = (temp >> 12) * 4;
	uint8_t reserved = (temp >> 6) & 0b111111;
	uint8_t flags = temp & 0b111111;

	uint16_t window_size = p[14] << 8 + p[15];
	uint16_t checksum = p[16] << 8 + p[17];
	uint16_t urgent = p[18] << 8 + p[19];

	printf("TCP Header:\n");
	printf("\tSource port: %u\n", source_port);
	printf("\tDest port: %u\n", dest_port);
	printf("\tSequence Number: %u\n", seq);
	printf("\tAcknowledgment Number: %u\n", ack);
	printf("\tHdr-len(in bytes): %u\n", hdrlen);
	printf("\tReserved: %u\n", reserved);
	printf("\tFlags: %u %u %u %u %u %u\n",
		flags >> 5, (flags >> 4) & 0b1, (flags >> 3) & 0b1, (flags >> 2) & 0b1,
		(flags >> 1) & 0b1, flags & 0b1);
	printf("\tWindow Size: %u\n", window_size);
	printf("\tChecksum: %u\n", checksum);
	printf("\tUrgent: %u\n", urgent);

	if(hdrlen == 0)
		hdrlen = 20;

	if(dest_port == 53)
		pack_num[DNS]++;
	else if(dest_port == 25 || dest_port == 587 || dest_port == 465 ||
			source_port == 25 || source_port == 587 || source_port == 465){
		pack_num[SMTP]++;
		printf("SMTP Payload:\n");
		print_mail(p+hdrlen);
	}else if(dest_port == 995 || dest_port == 110 || 
			source_port == 995 || source_port == 110){
		pack_num[POP]++;
		printf("POP Payload:\n");
		print_mail(p+hdrlen);
	}else if(dest_port == 993 || dest_port == 143 ||
			source_port == 993 || source_port == 143){
		pack_num[IMAP]++;
		printf("IMAP Payload:\n");
		print_mail(p+hdrlen);
	}else if(dest_port == 80 || dest_port == 443 ||
			source_port == 80 || source_port == 443){
		pack_num[HTTP]++;
		print_http(p+hdrlen);
	}
}

void print_ip(const u_char *p)
{
	uint8_t ver, header_len, service_type;
	ver = (*p & 0b11110000) >> 4;
	header_len = (*p & 0b00001111) * 4;
	service_type = p[1];

	uint16_t length = (p[2] << 8) + p[3];
	uint16_t id = (p[4] << 8) + p[5];
	uint8_t flags = p[6] >> 5;
	uint16_t offset = ((p[6] << 8) & 0x1F) + p[7];
	uint8_t ttl = p[8];
	uint8_t protocol = p[9];
	uint16_t checksum = (p[10] << 8) + p[11];
	

	printf("version: %u\n", ver);
	printf("Header Length(in bytes): %u\n", header_len);
	printf("Service type: %u\n", service_type);
	printf("Payload length: %u\n", length);
	printf("ID: %u\n", id);
	printf("Flags: %u %u %u\n", (flags >> 2), (flags >> 1) & 0b10, flags & 1);
	printf("Offset: %u\n", offset);
	printf("TTL: %u\n", ttl);
	printf("Protocol: %u\n", protocol);
	printf("Checksum: %u\n", checksum);
	printf("Source IP: %d.%d.%d.%d\n", p[12], p[13], p[14], p[15]);
	printf("Dest IP: %d.%d.%d.%d\n", p[16], p[17], p[18], p[19]);

	uint16_t udp_dest_port;
	switch(protocol){
	case 1:
		print_icmp(p+header_len);
		break;
	case 6:
		print_tcp(p+header_len);
		break;
	case 17:
		udp_dest_port = (p[header_len+2] << 8) + p[header_len+3];
		printf("UDP Dest port: %u\n", udp_dest_port);
		if(udp_dest_port == 53)
			pack_num[DNS]++;
	}
		
}

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	int i;
	uint16_t e_type;
	char *e_types;
	const u_char *data = p+14;

	u_int length = h->len;
	u_int caplen = h->caplen;

	printf("[\nDEST Address = ");
	for(i=0;i<7;i++)
		printf("%02X%c", p[i], ( i == 6 ? '\n' : ':'));

	e_type = p[12] * 256 + p[13];
	
	switch(e_type){
	case 0x800:
		e_types = "IPv4";
		pack_num[IP4]++;
		break;
	case 0x806:
		e_types = "ARP";
		pack_num[ARP]++;
		break;
	case 0x86DD:
		e_types = "IPv6";
		pack_num[IP6]++;
		break;
	default:
		e_types = "UNKNOWN";
	}
	printf("E_Type = %04X -> %s\n", e_type, e_types);

	switch(e_type){
	case 0x800:
		print_ip(data);
		break;
	case 0x806:
		print_arp(data);
		break;
	}

	default_print(p, caplen);
	printf("\n]\n");
}

