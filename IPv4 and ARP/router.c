#include <string.h>
#include <arpa/inet.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"

/*______________________________ PACKET CELL ______________________________*/
typedef struct packet_cell {
	int interface;
	uint32_t dhost_ip;
	char *packet;
	int packet_len;

	struct packet_cell *next;
	struct packet_cell *prev;
}packet_cell;

packet_cell *build_packet_cell(struct route_table_entry *rte, char *packet, size_t packet_len) {
	struct packet_cell *pck;
	pck = malloc(sizeof(struct packet_cell));

	pck->dhost_ip = rte->next_hop;
	pck->interface = rte->interface;
	pck->packet_len = packet_len;
	pck->packet = malloc(packet_len * sizeof(char));
	memcpy(pck->packet, packet, packet_len);
	pck->next = NULL;
	pck->prev = NULL;

	return pck;
}

/*______________________________ PACKET QUEUE ______________________________*/
typedef struct Packet_Queue {
	packet_cell *head;
	packet_cell *tail;
}Packet_Queue;

Packet_Queue *packet_queue;


Packet_Queue *packet_queue_init() {
	Packet_Queue *q;
	q = malloc(sizeof(Packet_Queue));
	q->head = NULL;
	q->tail = NULL;
	return q;
}

int packet_queue_empty(Packet_Queue *q) {
	return q->head == NULL;
}

void enq_packet(Packet_Queue *q, packet_cell *pck) {
	if(packet_queue_empty(q)) {
		q->head = q->tail = pck;
	} else {
		q->tail->next = pck;
		q->tail = q->tail->next;
	}
}

packet_cell *deq_packet(Packet_Queue *q) {
	if (packet_queue_empty(q))
		return NULL;

	packet_cell *pck = q->head;
	q->head = q->head->next;
	q->head->prev = NULL;
	return pck;
}

packet_cell *find_packet(Packet_Queue *q, int ip, int interface) {
	packet_cell *pck = q->head;
	while(pck != NULL) {
		if (pck->dhost_ip == ip && pck->interface == interface) {
			if (pck->prev != NULL)
				pck->prev = pck->next;
			if (pck->next != NULL)
				pck->next =  pck->prev;
			return pck;
		}
		pck = pck->next;
	}
	return NULL;
}


/*______________________________ ROUTING TABLE ______________________________*/
struct route_table_entry *rtable;
int rtable_len;
/* Returns a pointer (eg. &rtable[i]) to the best matching route, or NULL if there
   is no matching route. */
struct route_table_entry *get_best_route(uint32_t ip_dest) {
	struct route_table_entry *max = NULL;
	for (int i = 0; i < rtable_len; i++) {
		if (rtable[i].prefix == (ip_dest & rtable[i].mask) && 
			(max == NULL || rtable[i].mask > max->mask)) {
			max = &rtable[i];
		}
	}
	return max;
}


/*______________________________ ARP PROTOCOL ______________________________*/
struct arp_table_entry *arp_table;
int arp_table_len;
/* Returns a pointer to the matching arp_table_entry, or NULL if there is no match. */
struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if (given_ip == arp_table[i].ip)
			return &arp_table[i];
	}
	return NULL;
}

void send_arp_req(int interface, uint32_t requested_ip) {
	int ret;
	char *packet = malloc(MAX_PACKET_LEN * sizeof(char));
	size_t packet_len = sizeof(struct ether_header) + sizeof(struct arp_header);

	/* Get router's ip & mac addresses and convert them*/
	char* route_ip_string = get_interface_ip(interface);
	uint32_t router_ip = inet_addr(route_ip_string);
	uint8_t router_mac[6];
	get_interface_mac(interface, router_mac);

	/* build the Ethernet header */
	struct ether_header *eth = (struct ether_header *) packet;
	
	memcpy(eth->ether_shost, router_mac, (sizeof(eth->ether_shost)));
	for (int i = 0; i < 6; i++)
		eth->ether_dhost[i] = 0xff;
	eth->ether_type = htons(ETHER_TYPE_ARP);

	/* build the ARP protocol */
	struct arp_header *arp = (struct arp_header*)(packet + sizeof(struct ether_header));

	arp->htype = htons(1);
	arp->ptype = htons(ETHER_TYPE_IP);
	arp->hlen = 6;
	arp->plen = 4;
	arp->op = htons(1);
	memcpy(arp->sha, router_mac, (sizeof(arp->sha)));
	arp->spa = router_ip;
	for (int i = 0; i < 6; i++)
		arp->tha[i] = 0;
	arp->tpa = requested_ip;

	/* Send packet */
	ret = send_to_link(interface, packet, packet_len);
	DIE(ret < 0, "ARP - send req");

	free(packet);
}


/*______________________________ ICMP PROTOCOL ______________________________*/
void echo_icmp_reply(char *packet, size_t packet_len) {
	/* Parsing the packet */
	struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

	/* check if ICMP */
	if (ip_hdr->protocol != 1) {
		printf("Not ICMP protocol\n\n");
		return;
	}
	struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	/* check if Echo message */
	if (icmp_hdr->type != 8) {
		printf("Not echo icmp\n\n");
		return;
	}

	/* Modify ICMP type to Echo Reply */
	icmp_hdr->type = 0;

	/* Compute checksums */
	icmp_hdr->checksum = 0; // ICMP
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr)));
}

void build_icmp_err(uint8_t type, char *packet, size_t *packet_len, uint32_t router_ip) {
	/* Extract the IP packet */
	struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

	/* Build the icmp header */
	size_t icmp_pck_len = sizeof(struct icmphdr) + sizeof(struct iphdr) + 64;
	struct icmphdr *icmp_hdr = calloc(1, icmp_pck_len);
	icmp_hdr->code = 0;
	icmp_hdr->type = type;
	
	/* Build ICMP's Data section */
	char *data = (char *)icmp_hdr;
	data += sizeof(struct icmphdr);
	memcpy(data, ip_hdr, sizeof(struct iphdr) + 64);

	/* Compute ICMP checksum */
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, icmp_pck_len));

	/* Modify IP packet */
	ip_hdr->protocol = 1;
	ip_hdr->ttl = 64;
	ip_hdr->tot_len = htons(sizeof(struct iphdr)*2 + sizeof(struct icmphdr) + 64);

	ip_hdr->daddr = ip_hdr->saddr; // change addresses
	ip_hdr->saddr = router_ip;

	/* Build final Packet */
	memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, icmp_pck_len);
	*packet_len = sizeof(struct ether_header) + sizeof(struct iphdr) + icmp_pck_len;
	free(icmp_hdr);
}


/*______________________________ MAIN ______________________________*/
int main(int argc, char *argv[])
{
	// Do not modify this line
	init(argc - 2, argv + 2);

	/* Code to allocate the tables */
	rtable = malloc(sizeof(struct route_table_entry) * 100000); // rtable
	DIE(rtable == NULL, "route table memory");
	arp_table = malloc(100 * sizeof(struct arp_table_entry)); // arp_table
	arp_table_len = 0;
	/* Read Routing table */
	rtable_len = read_rtable(argv[1], rtable);

	/* Initialize queue */
	packet_queue = packet_queue_init();
	/* Initialize Broadcast mac addr */
	u_int8_t broadcast_mac[6];
	for (int i = 0; i < 6; i++)
			broadcast_mac[i] = 0xff;


	/* -----------------  LOOP ----------------- */
	while(1) {
		int ret;
		/* Packet elements */
		char packet[MAX_PACKET_LEN];
		size_t packet_len;
		int interface;
		/* Router elements */
		char* router_ip_string;
		uint32_t router_ip;
		uint8_t router_mac[6];
		

		/* --- Receive Packet --- */
		interface = recv_from_any_link(packet, &packet_len);
		DIE(interface < 0, "recv_from_any_links");
		
		/* Extract Router info */
		router_ip_string = get_interface_ip(interface);
		router_ip = inet_addr(router_ip_string);
		get_interface_mac(interface, router_mac);

		/* Parsing the packet */
		struct ether_header *eth_hdr = (struct ether_header *) packet;

		/* Packet validation - Router is the packet destination */
		if (memcmp(router_mac, eth_hdr->ether_dhost, 6) == 0) {
			
			/* ------------------ IP PACKET ------------------ */
			if (ntohs(eth_hdr->ether_type) == ETHER_TYPE_IP) {
				printf("Received IPv4 packet\n");

				/* Extract the IP packet */
				struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
				
				/* Verify checksum */
				uint16_t ip_packet_checksum = ip_hdr->check;
				ip_hdr->check = 0;
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
				if (ip_packet_checksum !=  ip_hdr->check) {
					printf("Invalid checksum\n");
					continue;
				}

				/* Verify Time To Live */
				int ttl = 0;
				if (ip_hdr->ttl <= 1) {
					printf("ICMP_TIME_EXCEEDED\n");
					build_icmp_err(ICMP_TIME_EXCEEDED, packet, &packet_len, router_ip);
					ttl = 1;
				}
				else {
					ip_hdr->ttl --;
				}

				/* Echo ICMP for router */
				if (ttl == 0 && router_ip == ip_hdr->daddr) {
					printf("Echo ICMP for router\n");
					echo_icmp_reply(packet, packet_len);
				}

				/* Find the ip of the next hop - in the Routing Table */
				struct route_table_entry *rte = get_best_route(ip_hdr->daddr);
				if (rte == NULL) {
					printf("--- Route-table failed ---\n");
					build_icmp_err(ICMP_HOST_UNREACHABLE, packet, &packet_len, router_ip);
					/* Compute checksum */
					ip_hdr->check = 0;
					ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
					printf("Checksum = %02x\n", ip_hdr->check);
					/* Modify Ethernet packet to be resent */
					memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
					memcpy(eth_hdr->ether_shost, router_mac, sizeof(eth_hdr->ether_shost));
					/* Send Packet */
					send_to_link(interface, packet, packet_len);
					printf("ICMP_HOST_UNREACHABLE sent\n\n");
					continue;
				}

				/* Compute checksum */
				ip_hdr->check = 0;
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
				printf("Checksum = %02x\n", ip_hdr->check);

				/* Search the mac address of the next hop in ARP-TABLE */
				struct arp_table_entry *ate = get_arp_entry(rte->next_hop);

				/* If not found, send ARP-REQUEST */
				if (ate == NULL) {
					printf("Not in ARP table, sending ARP request\n\n");
					/* Send ARP request */
					send_arp_req(rte->interface, rte->next_hop);
					/* Build Packet cell */
					struct packet_cell *pck = build_packet_cell(rte, packet, packet_len);
					/* Add packet cell in queue */
					enq_packet(packet_queue, pck);
					continue;
				}

				printf("Found in ARP table entry\n");
				/* Modify Ethernet packet to be resent */
				memcpy(eth_hdr->ether_dhost, ate->mac, sizeof(eth_hdr->ether_dhost));
				memcpy(eth_hdr->ether_shost, router_mac, sizeof(eth_hdr->ether_shost));

				/* Send Packet */
				send_to_link(rte->interface, packet, packet_len);
				printf("IPv4 Packet sent\n\n");

			}
			/* ------------------ ARP PACKET ------------------ */
			else if (ntohs(eth_hdr->ether_type) == ETHER_TYPE_ARP) {
				printf("ARP response packet received\n");

				/* Extract the ARP packet */
				struct arp_header *arp = (struct arp_header*)(packet + sizeof(struct ether_header));
				/* Check if valid */
				if (router_ip != arp->tpa || ntohs(arp->op) != 2 || packet_queue_empty(packet_queue)) {
					printf("Invalid ARP-response\n\n");
					continue;
				}
				/* Extract packet from packet list */
				printf("Searching for packet\n");
				struct packet_cell *pck = find_packet(packet_queue, arp->spa, interface);
				if (pck == NULL) {
					printf("Invalid pck (NULL)\n\n");
					continue;
				}
				printf("Packet found\n");

				/* Extract Ethernet Header */
				eth_hdr = (struct ether_header *) pck->packet;
				/* Save ARP result in ARP_TABLE */
				arp_table[arp_table_len].ip = pck->dhost_ip;
				memcpy(arp_table[arp_table_len].mac, arp->sha, 6);
				arp_table_len ++;

				/* Modify Ethernet packet to be resent */
				memcpy(eth_hdr->ether_dhost, arp->sha, 6);
				memcpy(eth_hdr->ether_shost, router_mac, 6);

				/* Send Packet */
				ret = send_to_link(pck->interface, pck->packet, pck->packet_len);
				DIE(ret < 0, "ARP - Waiting Packet");
				printf("Waiting Packet sent\n\n");

				free(pck->packet);
				free(pck);
			}
			else {
				printf("Invalid packet type\n\n");
				continue;
			}

		}/* Packet validation - Broadcast Packet (for everyone) */
		else if (memcmp(broadcast_mac, eth_hdr->ether_dhost, 6) == 0) {

			/* check if ARP packet */
			if (ntohs(eth_hdr->ether_type) != ETHER_TYPE_ARP)
				continue;
			/* Extract the ARP packet */
			struct arp_header *arp = (struct arp_header*)(packet + sizeof(struct ether_header));

			/* Check if valid */
			if (router_ip != arp->tpa || ntohs(arp->op) != 1)
					continue;
			printf("Received ARP BROADCAST request packet\n");

			/* change Ethernet header */
			memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, (sizeof(eth_hdr->ether_dhost)));
			memcpy(eth_hdr->ether_shost, router_mac, (sizeof(eth_hdr->ether_shost)));

			/* change ARP header */
			arp->op = htons(2);
			memcpy(arp->tha, arp->sha, sizeof(arp->tha));
			arp->tpa = arp->spa;
			memcpy(arp->sha, router_mac, sizeof(arp->sha));
			arp->spa = router_ip;

			/* Send the packet */
			ret = send_to_link(interface, packet, packet_len);
			DIE(ret < 0, "ARP - send reply");
			printf("ARP Reply Packet sent\n\n");
		}
		else {
			printf("Invalid packet\n\n");
		}
	}

	return 0;
}