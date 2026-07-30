/* STREAMING_CHUNK:Configuring system dependencies and constants... */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_tun.h>

/* ANSI Terminal Color Styling */
#define COLOR_RESET   "\033[0m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"

/* Ethernet & IP Protocol Constants */
#define ETH_P_IP      0x0800
#define ETH_P_ARP     0x0806
#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17

#define MAX_INTERFACES 8
#define MAX_ROUTES     64
#define MAX_ARP        128
#define MAX_ACL        32
#define PKT_BUF_SIZE   2048

/* STREAMING_CHUNK:Defining network packet headers... */
#pragma pack(push, 1)
typedef struct {
uint8_t  dst_mac[6];
uint8_t  src_mac[6];
uint16_t ethertype;
} EtherHeader;

typedef struct {
uint8_t  ihl_version; /* version:4 bits, ihl:4 bits */
uint8_t  tos;
uint16_t tot_len;
uint16_t id;
uint16_t frag_off;
uint8_t  ttl;
uint8_t  protocol;
uint16_t check;
uint32_t saddr;
uint32_t daddr;
} IPHeader;

typedef struct {
uint8_t  type;
uint8_t  code;
uint16_t checksum;
uint16_t id;
uint16_t sequence;
} ICMPHeader;

typedef struct {
uint16_t htype;
uint16_t ptype;
uint8_t  hlen;
uint8_t  plen;
uint16_t oper;
uint8_t  sha[6];
uint32_t spa;
uint8_t  tha[6];
uint32_t tpa;
} ARPHeader;
#pragma pack(pop)

/* STREAMING_CHUNK:Defining data structures for network state... */
typedef struct {
char name[IFNAMSIZ];
uint8_t mac[6];
uint32_t ip;
uint32_t netmask;
int tap_fd;
bool active;
uint64_t rx_pkts;
uint64_t tx_pkts;
uint64_t rx_bytes;
uint64_t tx_bytes;
} NetworkInterface;

typedef struct {
uint32_t network;
uint32_t netmask;
uint8_t  prefix_len;
uint32_t gateway;
char     if_name[IFNAMSIZ];
int      metric;
bool     active;
} RouteEntry;

typedef struct {
uint32_t ip;
uint8_t  mac[6];
time_t   updated_at;
bool     valid;
} ARPEntry;

typedef enum { ACL_ACTION_PERMIT, ACL_ACTION_DENY } ACLAction;

typedef struct {
int id;
uint32_t src_ip;
uint32_t src_mask;
uint32_t dst_ip;
uint32_t dst_mask;
uint8_t  protocol;
ACLAction action;
bool active;
} ACLRule;

typedef struct {
uint64_t total_received;
uint64_t total_forwarded;
uint64_t dropped_no_route;
uint64_t dropped_ttl_expired;
uint64_t dropped_acl;
uint64_t dropped_bad_checksum;
uint64_t icmp_replies_sent;
} RouterStatistics;

/* STREAMING_CHUNK:Initializing global state variables... */
static NetworkInterface g_interfaces[MAX_INTERFACES];
static int g_interface_count = 0;

static RouteEntry g_routes[MAX_ROUTES];
static int g_route_count = 0;

static ARPEntry g_arp_table[MAX_ARP];
static int g_arp_count = 0;

static ACLRule g_acl_table[MAX_ACL];
static int g_acl_count = 0;

static RouterStatistics g_stats = {0};
static pthread_mutex_t g_router_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_running = true;

/* STREAMING_CHUNK:Declaring function prototypes... */
uint16_t compute_checksum(const void *buf, size_t len);
uint8_t mask_to_prefix_len(uint32_t netmask);
bool add_route(const char *net_str, const char *mask_str, const char *gw_str, const char *if_name, int metric);
RouteEntry *lookup_route(uint32_t dest_ip);
void add_arp_entry(uint32_t ip, const uint8_t *mac);
bool lookup_arp(uint32_t ip, uint8_t *mac_out);
ACLAction check_acl(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol);
void send_icmp_response(NetworkInterface *in_if, EtherHeader *rx_eth, IPHeader *rx_ip, uint8_t type, uint8_t code);
void process_packet(uint8_t *buffer, size_t length, NetworkInterface *in_if);
int alloc_tap_device(char *dev_name);
void *interface_listener_thread(void *arg);
void simulate_packet(const char *src_ip_str, const char *dst_ip_str, uint8_t proto, uint8_t ttl);
void print_banner(void);
void print_help(void);
void cmd_show_routes(void);
void cmd_show_arp(void);
void cmd_show_interfaces(void);
void cmd_show_stats(void);
void run_cli_shell(void);

/* STREAMING_CHUNK:Implementing IP checksum calculation... */
uint16_t compute_checksum(const void *buf, size_t len) {
uint32_t sum = 0;
const uint16_t *ip = (const uint16_t *)buf;

while (len > 1) {
    sum += *ip++;
    len -= 2;
}

if (len > 0) {
    sum += *(const uint8_t *)ip;
}

while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
}

return (uint16_t)(~sum);


}

/* STREAMING_CHUNK:Implementing routing table operations... */
uint8_t mask_to_prefix_len(uint32_t netmask) {
uint32_t host_mask = ntohl(netmask);
uint8_t len = 0;
while (host_mask & 0x80000000) {
len++;
host_mask <<= 1;
}
return len;
}

bool add_route(const char *net_str, const char *mask_str, const char *gw_str, const char *if_name, int metric) {
pthread_mutex_lock(&g_router_mutex);
if (g_route_count >= MAX_ROUTES) {
pthread_mutex_unlock(&g_router_mutex);
return false;
}

RouteEntry *r = &g_routes[g_route_count];
inet_pton(AF_INET, net_str, &r->network);
inet_pton(AF_INET, mask_str, &r->netmask);
if (gw_str && strlen(gw_str) > 0) {
    inet_pton(AF_INET, gw_str, &r->gateway);
} else {
    r->gateway = 0;
}

r->prefix_len = mask_to_prefix_len(r->netmask);
strncpy(r->if_name, if_name, IFNAMSIZ - 1);
r->metric = metric;
r->active = true;

g_route_count++;
pthread_mutex_unlock(&g_router_mutex);
return true;


}

RouteEntry *lookup_route(uint32_t dest_ip) {
RouteEntry *best_match = NULL;
int max_prefix = -1;

for (int i = 0; i < g_route_count; i++) {
    if (!g_routes[i].active) continue;

    if ((dest_ip & g_routes[i].netmask) == (g_routes[i].network & g_routes[i].netmask)) {
        if (g_routes[i].prefix_len > max_prefix) {
            max_prefix = g_routes[i].prefix_len;
            best_match = &g_routes[i];
        }
    }
}
return best_match;


}

/* STREAMING_CHUNK:Implementing ARP table management... */
void add_arp_entry(uint32_t ip, const uint8_t *mac) {
pthread_mutex_lock(&g_router_mutex);
for (int i = 0; i < g_arp_count; i++) {
if (g_arp_table[i].ip == ip) {
memcpy(g_arp_table[i].mac, mac, 6);
g_arp_table[i].updated_at = time(NULL);
g_arp_table[i].valid = true;
pthread_mutex_unlock(&g_router_mutex);
return;
}
}

if (g_arp_count < MAX_ARP) {
    g_arp_table[g_arp_count].ip = ip;
    memcpy(g_arp_table[g_arp_count].mac, mac, 6);
    g_arp_table[g_arp_count].updated_at = time(NULL);
    g_arp_table[g_arp_count].valid = true;
    g_arp_count++;
}
pthread_mutex_unlock(&g_router_mutex);


}

bool lookup_arp(uint32_t ip, uint8_t *mac_out) {
pthread_mutex_lock(&g_router_mutex);
for (int i = 0; i < g_arp_count; i++) {
if (g_arp_table[i].valid && g_arp_table[i].ip == ip) {
memcpy(mac_out, g_arp_table[i].mac, 6);
pthread_mutex_unlock(&g_router_mutex);
return true;
}
}
pthread_mutex_unlock(&g_router_mutex);
return false;
}

/* STREAMING_CHUNK:Implementing ACL firewall checks... */
ACLAction check_acl(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol) {
pthread_mutex_lock(&g_router_mutex);
for (int i = 0; i < g_acl_count; i++) {
ACLRule *rule = &g_acl_table[i];
if (!rule->active) continue;

    bool src_match = ((src_ip & rule->src_mask) == (rule->src_ip & rule->src_mask));
    bool dst_match = ((dst_ip & rule->dst_mask) == (rule->dst_ip & rule->dst_mask));
    bool proto_match = (rule->protocol == 0 || rule->protocol == protocol);

    if (src_match && dst_match && proto_match) {
        ACLAction act = rule->action;
        pthread_mutex_unlock(&g_router_mutex);
        return act;
    }
}
pthread_mutex_unlock(&g_router_mutex);
return ACL_ACTION_PERMIT;


}

/* STREAMING_CHUNK:Implementing ICMP packet generation... */
void send_icmp_response(NetworkInterface *in_if, EtherHeader *rx_eth, IPHeader *rx_ip, uint8_t type, uint8_t code) {
uint8_t pkt_buf[256];
memset(pkt_buf, 0, sizeof(pkt_buf));

EtherHeader *tx_eth = (EtherHeader *)pkt_buf;
IPHeader *tx_ip = (IPHeader *)(pkt_buf + sizeof(EtherHeader));
ICMPHeader *tx_icmp = (ICMPHeader *)(pkt_buf + sizeof(EtherHeader) + sizeof(IPHeader));

memcpy(tx_eth->dst_mac, rx_eth->src_mac, 6);
memcpy(tx_eth->src_mac, in_if->mac, 6);
tx_eth->ethertype = htons(ETH_P_IP);

tx_ip->ihl_version = (4 << 4) | (sizeof(IPHeader) / 4);
tx_ip->tos = 0;
tx_ip->tot_len = htons(sizeof(IPHeader) + sizeof(ICMPHeader));
tx_ip->id = htons(12345);
tx_ip->frag_off = 0;
tx_ip->ttl = 64;
tx_ip->protocol = IP_PROTO_ICMP;
tx_ip->saddr = in_if->ip;
tx_ip->daddr = rx_ip->saddr;
tx_ip->check = 0;
tx_ip->check = compute_checksum(tx_ip, sizeof(IPHeader));

tx_icmp->type = type;
tx_icmp->code = code;
tx_icmp->checksum = 0;

if (type == 0) {
    ICMPHeader *rx_icmp = (ICMPHeader *)((uint8_t *)rx_ip + ((rx_ip->ihl_version & 0x0F) * 4));
    tx_icmp->id = rx_icmp->id;
    tx_icmp->sequence = rx_icmp->sequence;
} else {
    tx_icmp->id = 0;
    tx_icmp->sequence = 0;
}

tx_icmp->checksum = compute_checksum(tx_icmp, sizeof(ICMPHeader));
size_t total_len = sizeof(EtherHeader) + sizeof(IPHeader) + sizeof(ICMPHeader);

if (in_if->tap_fd > 0) {
    ssize_t res = write(in_if->tap_fd, pkt_buf, total_len);
    (void)res;
}

g_stats.icmp_replies_sent++;
in_if->tx_pkts++;
in_if->tx_bytes += total_len;


}

/* STREAMING_CHUNK:Implementing core L3 packet processing... */
void process_packet(uint8_t *buffer, size_t length, NetworkInterface *in_if) {
pthread_mutex_lock(&g_router_mutex);
g_stats.total_received++;
in_if->rx_pkts++;
in_if->rx_bytes += length;
pthread_mutex_unlock(&g_router_mutex);

if (length < sizeof(EtherHeader)) return;

EtherHeader *eth = (EtherHeader *)buffer;
uint16_t ethertype = ntohs(eth->ethertype);

if (ethertype == ETH_P_ARP) {
    if (length < sizeof(EtherHeader) + sizeof(ARPHeader)) return;
    ARPHeader *arp = (ARPHeader *)(buffer + sizeof(EtherHeader));
    add_arp_entry(arp->spa, arp->sha);
    return;
}

if (ethertype == ETH_P_IP) {
    if (length < sizeof(EtherHeader) + sizeof(IPHeader)) return;

    IPHeader *ip = (IPHeader *)(buffer + sizeof(EtherHeader));
    size_t ip_hdr_len = (ip->ihl_version & 0x0F) * 4;

    uint16_t rx_check = ip->check;
    ip->check = 0;
    if (compute_checksum(ip, ip_hdr_len) != rx_check) {
        pthread_mutex_lock(&g_router_mutex);
        g_stats.dropped_bad_checksum++;
        pthread_mutex_unlock(&g_router_mutex);
        return;
    }
    ip->check = rx_check;

    if (check_acl(ip->saddr, ip->daddr, ip->protocol) == ACL_ACTION_DENY) {
        pthread_mutex_lock(&g_router_mutex);
        g_stats.dropped_acl++;
        pthread_mutex_unlock(&g_router_mutex);
        return;
    }

    if (ip->daddr == in_if->ip) {
        if (ip->protocol == IP_PROTO_ICMP) {
            ICMPHeader *icmp = (ICMPHeader *)(buffer + sizeof(EtherHeader) + ip_hdr_len);
            if (icmp->type == 8) {
                send_icmp_response(in_if, eth, ip, 0, 0);
            }
        }
        return;
    }

    if (ip->ttl <= 1) {
        pthread_mutex_lock(&g_router_mutex);
        g_stats.dropped_ttl_expired++;
        pthread_mutex_unlock(&g_router_mutex);
        send_icmp_response(in_if, eth, ip, 11, 0);
        return;
    }

    RouteEntry *route = lookup_route(ip->daddr);
    if (!route) {
        pthread_mutex_lock(&g_router_mutex);
        g_stats.dropped_no_route++;
        pthread_mutex_unlock(&g_router_mutex);
        send_icmp_response(in_if, eth, ip, 3, 0);
        return;
    }

    NetworkInterface *out_if = NULL;
    for (int i = 0; i < g_interface_count; i++) {
        if (strcmp(g_interfaces[i].name, route->if_name) == 0) {
            out_if = &g_interfaces[i];
            break;
        }
    }
    if (!out_if) return;

    ip->ttl--;
    ip->check = 0;
    ip->check = compute_checksum(ip, ip_hdr_len);

    uint32_t next_hop = (route->gateway != 0) ? route->gateway : ip->daddr;
    uint8_t next_hop_mac[6];
    if (!lookup_arp(next_hop, next_hop_mac)) {
        memset(next_hop_mac, 0xFF, 6);
    }

    memcpy(eth->src_mac, out_if->mac, 6);
    memcpy(eth->dst_mac, next_hop_mac, 6);

    if (out_if->tap_fd > 0) {
        ssize_t res = write(out_if->tap_fd, buffer, length);
        (void)res;
    }

    pthread_mutex_lock(&g_router_mutex);
    g_stats.total_forwarded++;
    out_if->tx_pkts++;
    out_if->tx_bytes += length;
    pthread_mutex_unlock(&g_router_mutex);
}


}

/* STREAMING_CHUNK:Implementing TAP device allocation... */
int alloc_tap_device(char *dev_name) {
struct ifreq ifr;
int fd, err;

if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    return -1;
}

memset(&ifr, 0, sizeof(ifr));
ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
if (*dev_name) {
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);
}

if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    close(fd);
    return err;
}

strncpy(dev_name, ifr.ifr_name, IFNAMSIZ - 1);
return fd;


}

/* STREAMING_CHUNK:Implementing interface listener worker... */
void *interface_listener_thread(void *arg) {
NetworkInterface *iface = (NetworkInterface *)arg;
uint8_t buffer[PKT_BUF_SIZE];

while (g_running) {
    if (iface->tap_fd <= 0) {
        usleep(100000);
        continue;
    }

    ssize_t nread = read(iface->tap_fd, buffer, sizeof(buffer));
    if (nread > 0) {
        process_packet(buffer, (size_t)nread, iface);
    }
}
return NULL;


}

/* STREAMING_CHUNK:Building synthetic packet simulator... */
void simulate_packet(const char *src_ip_str, const char *dst_ip_str, uint8_t proto, uint8_t ttl) {
uint8_t frame[128];
memset(frame, 0, sizeof(frame));

EtherHeader *eth = (EtherHeader *)frame;
IPHeader *ip = (IPHeader *)(frame + sizeof(EtherHeader));

uint8_t src_mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
uint8_t dst_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};

memcpy(eth->src_mac, src_mac, 6);
memcpy(eth->dst_mac, dst_mac, 6);
eth->ethertype = htons(ETH_P_IP);

ip->ihl_version = (4 << 4) | 5;
ip->tos = 0;
ip->tot_len = htons(sizeof(IPHeader) + 20);
ip->id = htons(0x4321);
ip->frag_off = 0;
ip->ttl = ttl;
ip->protocol = proto;
inet_pton(AF_INET, src_ip_str, &ip->saddr);
inet_pton(AF_INET, dst_ip_str, &ip->daddr);
ip->check = 0;
ip->check = compute_checksum(ip, sizeof(IPHeader));

printf(COLOR_CYAN "\n[SIMULATOR] Injecting synthetic packet:\n" COLOR_RESET);
printf("  Src IP: %s -> Dst IP: %s (TTL: %d, Protocol: %d)\n", src_ip_str, dst_ip_str, ttl, proto);

if (g_interface_count > 0) {
    process_packet(frame, sizeof(EtherHeader) + sizeof(IPHeader) + 20, &g_interfaces[0]);
    printf(COLOR_GREEN "  Packet processed successfully!\n" COLOR_RESET);
} else {
    printf(COLOR_RED "  No interface active to receive packet!\n" COLOR_RESET);
}


}

/* STREAMING_CHUNK:Developing CLI display helpers... */
void print_banner(void) {
printf(COLOR_BOLD COLOR_BLUE);
printf("=\n");
printf("   Linux Network Router Application (C Engine)           \n");
printf("   L3 IP Forwarding | LPM | ARP Cache | ACL Engine       \n");
printf("=\n" COLOR_RESET);
}

void print_help(void) {
printf(COLOR_YELLOW "\nAvailable Router Commands:\n" COLOR_RESET);
printf("  " COLOR_BOLD "show routes" COLOR_RESET "              Display full IPv4 routing table\n");
printf("  " COLOR_BOLD "show arp" COLOR_RESET "                 Display ARP cache table\n");
printf("  " COLOR_BOLD "show interfaces" COLOR_RESET "          Display list of configured interfaces\n");
printf("  " COLOR_BOLD "show stats" COLOR_RESET "               Display packet routing engine metrics\n");
printf("  " COLOR_BOLD "add route   <gw|0>  [metric]" COLOR_RESET "\n");
printf("                           Add static route\n");
printf("  " COLOR_BOLD "add arp  " COLOR_RESET "       Manually bind IP to MAC address\n");
printf("  " COLOR_BOLD "sim <src_ip> <dst_ip> [proto] [ttl]" COLOR_RESET "\n");
printf("                           Simulate packet and test L3 lookup\n");
printf("  " COLOR_BOLD "help" COLOR_RESET "                     Show command usage\n");
printf("  " COLOR_BOLD "exit" COLOR_RESET "                     Shutdown router application\n\n");
}

/* STREAMING_CHUNK:Developing CLI command handlers... */
void cmd_show_routes(void) {
printf(COLOR_BOLD "\n%-18s %-18s %-18s %-10s %-8s\n" COLOR_RESET, "Network", "Netmask", "Gateway", "Interface", "Metric");
printf("-----------------------------------------------------------------------\n");

char net[16], mask[16], gw[16];
pthread_mutex_lock(&g_router_mutex);
for (int i = 0; i < g_route_count; i++) {
    if (!g_routes[i].active) continue;

    inet_ntop(AF_INET, &g_routes[i].network, net, sizeof(net));
    inet_ntop(AF_INET, &g_routes[i].netmask, mask, sizeof(mask));
    if (g_routes[i].gateway != 0) {
        inet_ntop(AF_INET, &g_routes[i].gateway, gw, sizeof(gw));
    } else {
        strcpy(gw, "0.0.0.0");
    }
    printf("%-18s %-18s %-18s %-10s %-8d\n", net, mask, gw, g_routes[i].if_name, g_routes[i].metric);
}
pthread_mutex_unlock(&g_router_mutex);
printf("\n");


}

void cmd_show_arp(void) {
printf(COLOR_BOLD "\n%-18s %-20s %-12s\n" COLOR_RESET, "IP Address", "MAC Address", "Status");
printf("--------------------------------------------------\n");
char ip[16], mac_str[18];

pthread_mutex_lock(&g_router_mutex);
for (int i = 0; i < g_arp_count; i++) {
    if (!g_arp_table[i].valid) continue;
    inet_ntop(AF_INET, &g_arp_table[i].ip, ip, sizeof(ip));
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             g_arp_table[i].mac[0], g_arp_table[i].mac[1], g_arp_table[i].mac[2],
             g_arp_table[i].mac[3], g_arp_table[i].mac[4], g_arp_table[i].mac[5]);
    printf("%-18s %-20s %-12s\n", ip, mac_str, "REACHABLE");
}
pthread_mutex_unlock(&g_router_mutex);
printf("\n");


}

void cmd_show_interfaces(void) {
printf(COLOR_BOLD "\n%-10s %-18s %-20s %-10s %-10s\n" COLOR_RESET, "Device", "IP Address", "MAC Address", "RX Pkts", "TX Pkts");
printf("-------------------------------------------------------------------------\n");
char ip[16], mac_str[18];

for (int i = 0; i < g_interface_count; i++) {
    NetworkInterface *iface = &g_interfaces[i];
    inet_ntop(AF_INET, &iface->ip, ip, sizeof(ip));
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             iface->mac[0], iface->mac[1], iface->mac[2],
             iface->mac[3], iface->mac[4], iface->mac[5]);
    printf("%-10s %-18s %-20s %-10llu %-10llu\n", iface->name, ip, mac_str, 
           (unsigned long long)iface->rx_pkts, (unsigned long long)iface->tx_pkts);
}
printf("\n");


}

void cmd_show_stats(void) {
printf(COLOR_BOLD "\n--- Router Performance Statistics ---\n" COLOR_RESET);
printf(" Total Packets Received     : %llu\n", (unsigned long long)g_stats.total_received);
printf(" Total Packets Forwarded    : %llu\n", (unsigned long long)g_stats.total_forwarded);
printf(" ICMP Replies Sent          : %llu\n", (unsigned long long)g_stats.icmp_replies_sent);
printf(COLOR_RED " Dropped (No Route)         : %llu\n" COLOR_RESET, (unsigned long long)g_stats.dropped_no_route);
printf(COLOR_RED " Dropped (TTL Expired)      : %llu\n" COLOR_RESET, (unsigned long long)g_stats.dropped_ttl_expired);
printf(COLOR_RED " Dropped (ACL Blocked)      : %llu\n" COLOR_RESET, (unsigned long long)g_stats.dropped_acl);
printf(COLOR_RED " Dropped (Bad Checksum)     : %llu\n\n" COLOR_RESET, (unsigned long long)g_stats.dropped_bad_checksum);
}

/* STREAMING_CHUNK:Developing interactive shell loop... */
void run_cli_shell(void) {
char line[256];
print_banner();
print_help();

while (g_running) {
    printf(COLOR_BOLD COLOR_GREEN "Router# " COLOR_RESET);
    fflush(stdout);

    if (!fgets(line, sizeof(line), stdin)) break;

    line[strcspn(line, "\r\n")] = 0;
    if (strlen(line) == 0) continue;

    if (strcmp(line, "help") == 0) {
        print_help();
    } else if (strcmp(line, "show routes") == 0) {
        cmd_show_routes();
    } else if (strcmp(line, "show arp") == 0) {
        cmd_show_arp();
    } else if (strcmp(line, "show interfaces") == 0) {
        cmd_show_interfaces();
    } else if (strcmp(line, "show stats") == 0) {
        cmd_show_stats();
    } else if (strncmp(line, "sim ", 4) == 0) {
        char src[32], dst[32];
        int proto = 1, ttl = 64;
        if (sscanf(line + 4, "%s %s %d %d", src, dst, &proto, &ttl) >= 2) {
            simulate_packet(src, dst, (uint8_t)proto, (uint8_t)ttl);
        } else {
            printf("Usage: sim <src_ip> <dst_ip> [protocol] [ttl]\n");
        }
    } else if (strncmp(line, "add route ", 10) == 0) {
        char net[32], mask[32], gw[32], dev[32];
        int metric = 10;
        if (sscanf(line + 10, "%s %s %s %s %d", net, mask, gw, dev, &metric) >= 4) {
            const char *gw_ptr = (strcmp(gw, "0") == 0) ? NULL : gw;
            if (add_route(net, mask, gw_ptr, dev, metric)) {
                printf(COLOR_GREEN "Route added successfully.\n" COLOR_RESET);
            } else {
                printf(COLOR_RED "Failed to add route.\n" COLOR_RESET);
            }
        } else {
            printf("Usage: add route <net> <mask> <gw|0> <dev> [metric]\n");
        }
    } else if (strncmp(line, "add arp ", 8) == 0) {
        char ip_str[32], mac_str[32];
        if (sscanf(line + 8, "%s %s", ip_str, mac_str) == 2) {
            uint32_t ip;
            uint8_t mac[6];
            inet_pton(AF_INET, ip_str, &ip);
            if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                       &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
                add_arp_entry(ip, mac);
                printf(COLOR_GREEN "ARP binding added.\n" COLOR_RESET);
            } else {
                printf(COLOR_RED "Invalid MAC format. Use XX:XX:XX:XX:XX:XX\n" COLOR_RESET);
            }
        } else {
            printf("Usage: add arp <ip> <mac>\n");
        }
    } else if (strcmp(line, "exit") == 0 || strcmp(line, "quit") == 0) {
        printf(COLOR_YELLOW "Shutting down router application...\n" COLOR_RESET);
        g_running = false;
        break;
    } else {
        printf("Unknown command: '%s'. Type 'help' for available commands.\n", line);
    }
}


}

/* STREAMING_CHUNK:Defining main entry point... */
int main(int argc, char *argv[]) {
NetworkInterface *if0 = &g_interfaces[0];
strncpy(if0->name, "eth0", IFNAMSIZ - 1);
inet_pton(AF_INET, "192.168.1.1", &if0->ip);
inet_pton(AF_INET, "255.255.255.0", &if0->netmask);
uint8_t mac0[6] = {0x00, 0x50, 0x56, 0x00, 0x00, 0x01};
memcpy(if0->mac, mac0, 6);
if0->tap_fd = -1;
if0->active = true;

NetworkInterface *if1 = &g_interfaces[1];
strncpy(if1->name, "eth1", IFNAMSIZ - 1);
inet_pton(AF_INET, "10.0.0.1", &if1->ip);
inet_pton(AF_INET, "255.255.255.0", &if1->netmask);
uint8_t mac1[6] = {0x00, 0x50, 0x56, 0x00, 0x00, 0x02};
memcpy(if1->mac, mac1, 6);
if1->tap_fd = -1;
if1->active = true;

g_interface_count = 2;

add_route("192.168.1.0", "255.255.255.0", NULL, "eth0", 0);
add_route("10.0.0.0", "255.255.255.0", NULL, "eth1", 0);
add_route("0.0.0.0", "0.0.0.0", "10.0.0.254", "eth1", 100);

uint8_t client_mac[6] = {0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33};
uint32_t client_ip;
inet_pton(AF_INET, "192.168.1.50", &client_ip);
add_arp_entry(client_ip, client_mac);

uint8_t gw_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
uint32_t gw_ip;
inet_pton(AF_INET, "10.0.0.254", &gw_ip);
add_arp_entry(gw_ip, gw_mac);

if (getuid() == 0) {
    printf(COLOR_GREEN "[+] Root privileges detected. Initializing Linux TAP devices...\n" COLOR_RESET);
    char tap0_name[IFNAMSIZ] = "tap_r0";
    int fd0 = alloc_tap_device(tap0_name);
    if (fd0 > 0) {
        if0->tap_fd = fd0;
        strncpy(if0->name, tap0_name, IFNAMSIZ - 1);
        printf("    Created TAP Interface: %s\n", tap0_name);
        pthread_t thread0;
        pthread_create(&thread0, NULL, interface_listener_thread, if0);
    }
} else {
    printf(COLOR_YELLOW "[!] Operating in Simulation Mode (Non-root user).\n" COLOR_RESET);
    printf("    (Run with 'sudo' to bind to real Linux kernel TAP interfaces)\n");
}

run_cli_shell();

return 0;


}