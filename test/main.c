#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#ifdef _WIN32
    #ifndef _WIN32_WINNT
        #define _WIN32_WINNT 0x0600
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #include <windows.h>
    #include <shellapi.h>
    #include <process.h>

    #pragma comment(lib, "iphlpapi.lib")
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "shell32.lib")

    typedef HANDLE thread_t;
    typedef CRITICAL_SECTION mutex_t;
    #define MUTEX_INIT(m) InitializeCriticalSection(m)
    #define MUTEX_LOCK(m) EnterCriticalSection(m)
    #define MUTEX_UNLOCK(m) LeaveCriticalSection(m)
    #define SLEEP_MS(ms) Sleep(ms)
#else
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
    #include <pthread.h>

    typedef pthread_t thread_t;
    typedef pthread_mutex_t mutex_t;
    #define MUTEX_INIT(m) pthread_mutex_init(m, NULL)
    #define MUTEX_LOCK(m) pthread_mutex_lock(m)
    #define MUTEX_UNLOCK(m) pthread_mutex_unlock(m)
    #define SLEEP_MS(ms) usleep((ms) * 1000)
#endif

#define MAX_CLIENTS 64

// Router Sharing Modes
typedef enum {
    MODE_WIFI_AP = 1,    // Shares internet via Wireless Access Point (WinRT Hotspot / hostapd)
    MODE_LAN_GATEWAY = 2 // Shares internet via Wired Connection (USB-to-LAN NAT Gateway)
} RouterMode;

// Router Configuration Structure
typedef struct {
    char wan_iface[64];   // WAN Interface connected to Internet (e.g. Ethernet 7)
    char lan_iface[64];   // Target Adapter (e.g. Wi-Fi 2, Ethernet 2)
    char ssid[64];        // Hotspot SSID Name
    char password[64];    // Hotspot Password
    RouterMode mode;
} RouterConfig;

// Connected Client Structure
typedef struct {
    char ip[16];
    char mac[18];
    bool active;
    bool blocked;
    time_t first_seen;
    int time_limit_sec;   // 0 = Unlimited
    int bandwidth_kbps;   // 0 = Unlimited
} Client;

// Global State
RouterConfig g_config;
Client g_clients[MAX_CLIENTS];
int g_client_count = 0;
mutex_t g_db_mutex;
bool g_running = true;

// Function Prototypes
void configure_router_setup(void);
void enable_ip_forwarding(void);
void initialize_network_sharing(void);
void scan_network_clients(void);
void block_device(Client *client);
void unblock_device(Client *client);
void apply_bandwidth_limit(Client *client, int kbps);
void display_dashboard(void);
bool is_valid_unicast_host(unsigned char *mac, unsigned long ip_addr);

#ifdef _WIN32
BOOL IsRunAsAdmin(void);
void ElevatePrivileges(int argc, char *argv[]);
#endif

// Background Thread for Network Scanning & Timer Enforcements
#ifdef _WIN32
unsigned __stdcall enforcer_thread(void *arg)
#else
void *enforcer_thread(void *arg)
#endif
{
    while (g_running) {
        MUTEX_LOCK(&g_db_mutex);
        scan_network_clients();

        time_t now = time(NULL);
        for (int i = 0; i < g_client_count; i++) {
            Client *c = &g_clients[i];
            if (!c->active) continue;

            // Session Timeout Checking
            if (c->time_limit_sec > 0 && !c->blocked) {
                double elapsed = difftime(now, c->first_seen);
                if (elapsed >= c->time_limit_sec) {
                    printf("\n[!] TIME EXPIRED for Client [%s | %s]! Disconnecting...\n", c->ip, c->mac);
                    block_device(c);
                }
            }
        }
        MUTEX_UNLOCK(&g_db_mutex);

        SLEEP_MS(3000); // Poll every 3 seconds
    }
    return 0;
}

int main(int argc, char *argv[]) {
#ifdef _WIN32
    ElevatePrivileges(argc, argv);
#endif

    MUTEX_INIT(&g_db_mutex);

    // Step 1: Configuration Prompt
    configure_router_setup();

    // Step 2: Routing Setup & Modern Hotspot Start
    enable_ip_forwarding();
    initialize_network_sharing();

    // Step 3: Launch Background Monitoring
    thread_t thread_id;
#ifdef _WIN32
    thread_id = (HANDLE)_beginthreadex(NULL, 0, enforcer_thread, NULL, 0, NULL);
#else
    pthread_create(&thread_id, NULL, enforcer_thread, NULL);
#endif

    printf("\n[*] Starting Live Gateway Engine...\n");
    SLEEP_MS(1500);

    // Step 4: Interactive Control Dashboard
    int choice = -1;
    while (choice != 0) {
        display_dashboard();
        printf("\n=== Router Control Panel ===\n");
        printf("1. Refresh Dashboard\n");
        printf("2. Set Session Timer for Client\n");
        printf("3. Disconnect / Block Client\n");
        printf("4. Unblock Client\n");
        printf("5. Set Bandwidth Limit (Kbps)\n");
        printf("0. Shutdown Router Manager\n");
        printf("Select Option: ");
        
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            continue;
        }

        MUTEX_LOCK(&g_db_mutex);
        if (choice == 2) {
            int idx, minutes;
            printf("Enter Client ID #: ");
            scanf("%d", &idx);
            if (idx >= 0 && idx < g_client_count) {
                printf("Enter internet access time limit (in minutes): ");
                scanf("%d", &minutes);
                g_clients[idx].time_limit_sec = minutes * 60;
                g_clients[idx].first_seen = time(NULL);
                printf("[+] Timer set to %d minutes for %s\n", minutes, g_clients[idx].ip);
                SLEEP_MS(1000);
            }
        } else if (choice == 3) {
            int idx;
            printf("Enter Client ID # to disconnect/block: ");
            scanf("%d", &idx);
            if (idx >= 0 && idx < g_client_count) {
                block_device(&g_clients[idx]);
                SLEEP_MS(1000);
            }
        } else if (choice == 4) {
            int idx;
            printf("Enter Client ID # to unblock: ");
            scanf("%d", &idx);
            if (idx >= 0 && idx < g_client_count) {
                unblock_device(&g_clients[idx]);
                SLEEP_MS(1000);
            }
        } else if (choice == 5) {
            int idx, kbps;
            printf("Enter Client ID #: ");
            scanf("%d", &idx);
            if (idx >= 0 && idx < g_client_count) {
                printf("Enter max bandwidth (Kbps, 0 = unlimited): ");
                scanf("%d", &kbps);
                apply_bandwidth_limit(&g_clients[idx], kbps);
                SLEEP_MS(1000);
            }
        }
        MUTEX_UNLOCK(&g_db_mutex);
    }

    g_running = false;
    printf("\nShutting down Gateway Manager...\n");
    SLEEP_MS(1000);
    return 0;
}

void configure_router_setup(void) {
    system(
#ifdef _WIN32
        "cls"
#else
        "clear"
#endif
    );

    printf("==================================================\n");
    printf("         ROUTER INTERFACE & NETWORK SETUP         \n");
    printf("==================================================\n\n");

    printf("Select Network Sharing Mode:\n");
    printf("  [1] USB to Wi-Fi (Create Wireless Access Point)\n");
    printf("  [2] USB to LAN / Ethernet Gateway (Share Internet via Wired Cable)\n");
    printf("Choice [1-2]: ");
    scanf("%d", (int*)&g_config.mode);
    while (getchar() != '\n'); 

#ifdef _WIN32
    printf("\nEnter Internet Source Interface Name (e.g., 'Ethernet 7', 'Wi-Fi'): ");
#else
    printf("\nEnter Internet Source Interface Name (e.g., 'eth0', 'wlan0'): ");
#endif
    fgets(g_config.wan_iface, sizeof(g_config.wan_iface), stdin);
    g_config.wan_iface[strcspn(g_config.wan_iface, "\r\n")] = 0;

    if (g_config.mode == MODE_WIFI_AP) {
#ifdef _WIN32
        printf("Enter USB/Built-in Wi-Fi Interface Name (e.g., 'Wi-Fi', 'Wi-Fi 2'): ");
#else
        printf("Enter USB Wireless Adapter Interface Name (e.g., 'wlan1'): ");
#endif
        fgets(g_config.lan_iface, sizeof(g_config.lan_iface), stdin);
        g_config.lan_iface[strcspn(g_config.lan_iface, "\r\n")] = 0;

        printf("Enter Hotspot SSID Name: ");
        fgets(g_config.ssid, sizeof(g_config.ssid), stdin);
        g_config.ssid[strcspn(g_config.ssid, "\r\n")] = 0;

        printf("Enter Hotspot Password (Min 8 chars): ");
        fgets(g_config.password, sizeof(g_config.password), stdin);
        g_config.password[strcspn(g_config.password, "\r\n")] = 0;

    } else if (g_config.mode == MODE_LAN_GATEWAY) {
#ifdef _WIN32
        printf("Enter USB-to-LAN / Ethernet Sharing Interface (e.g., 'Ethernet 2'): ");
#else
        printf("Enter USB-to-LAN Adapter Interface Name (e.g., 'eth1'): ");
#endif
        fgets(g_config.lan_iface, sizeof(g_config.lan_iface), stdin);
        g_config.lan_iface[strcspn(g_config.lan_iface, "\r\n")] = 0;
    }
}

void enable_ip_forwarding(void) {
#ifdef _WIN32
    system("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 1 /f > nul 2>&1");
    printf("[+] Windows IP Packet Routing Enabled.\n");
#else
    system("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1");
    printf("[+] Linux IP Packet Forwarding Enabled.\n");
#endif
}

void initialize_network_sharing(void) {
    if (g_config.mode == MODE_WIFI_AP) {
        printf("[*] Starting Wireless Access Point '%s' on [%s]...\n", g_config.ssid, g_config.lan_iface);
#ifdef _WIN32
        FILE *fp = fopen("start_hotspot.ps1", "w");
        if (fp) {
            fprintf(fp,
                "$ErrorActionPreference = 'Stop'\n"
                "try {\n"
                "    # 1. Force Start Hotspot & Connection Sharing Services\n"
                "    Set-Service -Name 'icssvc' -StartupType Automatic -ErrorAction SilentlyContinue\n"
                "    Start-Service -Name 'icssvc' -ErrorAction SilentlyContinue\n"
                "    Set-Service -Name 'SharedAccess' -StartupType Automatic -ErrorAction SilentlyContinue\n"
                "    Start-Service -Name 'SharedAccess' -ErrorAction SilentlyContinue\n"
                "\n"
                "    # 2. Enable Target Wi-Fi Adapter\n"
                "    Enable-NetAdapter -Name '%s' -Confirm:$false -ErrorAction SilentlyContinue\n"
                "\n"
                "    # 3. Retrieve Active WAN Connection Profile\n"
                "    $profile = [Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime]::GetInternetConnectionProfile()\n"
                "    if (-not $profile) {\n"
                "        Write-Host '[!] ERROR: WAN interface has no active Internet profile in Windows.' -ForegroundColor Red\n"
                "        Write-Host '[!] Connect WAN to the Internet first so NCSI validates connectivity.' -ForegroundColor Yellow\n"
                "        exit\n"
                "    }\n"
                "\n"
                "    # 4. Check Tethering Capability via Static Method\n"
                "    $cap = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime]::GetTetheringCapabilityFromConnectionProfile($profile)\n"
                "    if ($cap -ne 'Capable') {\n"
                "        Write-Host (\"[-] Tethering Capability Status: \" + $cap) -ForegroundColor Red\n"
                "        if ($cap -eq 'DisabledByHardwareLimitation') {\n"
                "            Write-Host '[!] Reason: Wi-Fi adapter or driver does not support Wi-Fi Direct / AP Mode.' -ForegroundColor Yellow\n"
                "        } elseif ($cap -eq 'DisabledByGroupPolicy') {\n"
                "            Write-Host '[!] Reason: Mobile Hotspot is disabled in Windows Group Policy.' -ForegroundColor Yellow\n"
                "        }\n"
                "        exit\n"
                "    }\n"
                "\n"
                "    # 5. Create Tethering Manager Instance\n"
                "    $tether = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime]::CreateFromConnectionProfile($profile)\n"
                "    if (-not $tether) {\n"
                "        Write-Host '[-] ERROR: Unable to instantiate Tethering Manager from connection profile.' -ForegroundColor Red\n"
                "        exit\n"
                "    }\n"
                "\n"
                "    # 6. Configure SSID, Password, and 2.4GHz Band\n"
                "    $config = $tether.GetCurrentAccessPointConfiguration()\n"
                "    $config.Ssid = '%s'\n"
                "    $config.Passphrase = '%s'\n"
                "    try { $config.Band = [Windows.Networking.NetworkOperators.TetheringBand]::TwoPointFourGigahertz } catch {}\n"
                "    $tether.ConfigureAccessPointAsync($config).GetAwaiter().GetResult() | Out-Null\n"
                "\n"
                "    # 7. Start Hotspot\n"
                "    $res = $tether.StartTetheringAsync().GetAwaiter().GetResult()\n"
                "    if ($res.Status -eq 'Success') {\n"
                "        Write-Host '[+] SUCCESS: Access Point is broadcasting on 2.4GHz!' -ForegroundColor Green\n"
                "    } else {\n"
                "        Write-Host ('[-] Hotspot Start Failed. Windows Status: ' + $res.Status) -ForegroundColor Red\n"
                "    }\n"
                "} catch {\n"
                "    Write-Host ('[-] Critical Exception: ' + $_.Exception.Message) -ForegroundColor Red\n"
                "}\n",
                g_config.lan_iface, g_config.wan_iface, g_config.ssid, g_config.password);
            fclose(fp);

            system("powershell -ExecutionPolicy Bypass -File start_hotspot.ps1");
            remove("start_hotspot.ps1");
        }
#else
        FILE *fp = fopen("/tmp/hostapd.conf", "w");
        if (fp) {
            fprintf(fp,
                "interface=%s\n"
                "driver=nl80211\n"
                "ssid=%s\n"
                "hw_mode=g\n"
                "channel=7\n"
                "wpa=2\n"
                "wpa_passphrase=%s\n"
                "wpa_key_mgmt=WPA-PSK\n",
                g_config.lan_iface, g_config.ssid, g_config.password);
            fclose(fp);
            system("hostapd -B /tmp/hostapd.conf > /dev/null 2>&1");
            printf("[+] Linux hostapd Access Point Active.\n");
        }
#endif
    } else if (g_config.mode == MODE_LAN_GATEWAY) {
        printf("[*] Configuring USB-to-LAN NAT Gateway from [%s] -> [%s]...\n", g_config.wan_iface, g_config.lan_iface);
#ifdef _WIN32
        FILE *fp = fopen("start_nat.ps1", "w");
        if (fp) {
            fprintf(fp,
                "New-NetIPAddress -InterfaceAlias '%s' -IPAddress 192.168.137.1 -PrefixLength 24 -ErrorAction SilentlyContinue | Out-Null\n"
                "Remove-NetNat -Name 'RouterNAT' -Confirm:$false -ErrorAction SilentlyContinue | Out-Null\n"
                "New-NetNat -Name 'RouterNAT' -InternalIPInterfaceAddressPrefix 192.168.137.0/24 | Out-Null\n"
                "Write-Host '[+] Windows USB-to-LAN NAT Gateway Active.'\n",
                g_config.lan_iface);
            fclose(fp);

            system("powershell -ExecutionPolicy Bypass -File start_nat.ps1");
            remove("start_nat.ps1");
        }
#else
        char cmd[1024];
        snprintf(cmd, sizeof(cmd),
            "ifconfig %s 192.168.10.1 netmask 255.255.255.0 up; "
            "iptables -t nat -A POSTROUTING -o %s -j MASQUERADE; "
            "iptables -A FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT; "
            "iptables -A FORWARD -i %s -o %s -j ACCEPT",
            g_config.lan_iface, g_config.wan_iface, g_config.wan_iface, g_config.lan_iface, g_config.lan_iface, g_config.wan_iface);
        system(cmd);
        printf("[+] Linux iptables NAT Gateway Active.\n");
#endif
    }
}


void block_device(Client *client) {
    char cmd[512];
    client->blocked = true;
#ifdef _WIN32
    snprintf(cmd, sizeof(cmd),
        "powershell -Command \"Remove-NetFirewallRule -DisplayName 'Block-%s' -ErrorAction SilentlyContinue; "
        "New-NetFirewallRule -DisplayName 'Block-%s' -Direction Inbound -Action Block -RemoteAddress %s | Out-Null\"",
        client->mac, client->mac, client->ip);
#else
    snprintf(cmd, sizeof(cmd), "iptables -I FORWARD -m mac --mac-source %s -j DROP", client->mac);
#endif
    system(cmd);
    printf("[+] DISCONNECTED/BLOCKED: %s (%s)\n", client->ip, client->mac);
}

void unblock_device(Client *client) {
    char cmd[512];
    client->blocked = false;
#ifdef _WIN32
    snprintf(cmd, sizeof(cmd),
        "powershell -Command \"Remove-NetFirewallRule -DisplayName 'Block-%s' -ErrorAction SilentlyContinue | Out-Null\"",
        client->mac);
#else
    snprintf(cmd, sizeof(cmd), "iptables -D FORWARD -m mac --mac-source %s -j DROP", client->mac);
#endif
    system(cmd);
    printf("[+] UNBLOCKED: %s (%s)\n", client->ip, client->mac);
}

void apply_bandwidth_limit(Client *client, int kbps) {
    client->bandwidth_kbps = kbps;
    char cmd[512];
#ifdef _WIN32
    if (kbps > 0) {
        int bits = kbps * 1000;
        snprintf(cmd, sizeof(cmd),
            "powershell -Command \"Remove-NetQosPolicy -Name 'Throttle-%s' -Confirm:$false -ErrorAction SilentlyContinue; "
            "New-NetQosPolicy -Name 'Throttle-%s' -IPAddressMatchCondition '%s' -ThrottleRateActionBitsPerSecond %d | Out-Null\"",
            client->ip, client->ip, client->ip, bits);
    } else {
        snprintf(cmd, sizeof(cmd),
            "powershell -Command \"Remove-NetQosPolicy -Name 'Throttle-%s' -Confirm:$false -ErrorAction SilentlyContinue | Out-Null\"",
            client->ip);
    }
#else
    if (kbps > 0) {
        snprintf(cmd, sizeof(cmd),
            "tc qdisc del dev %s root 2>/dev/null; "
            "tc qdisc add dev %s root handle 1: htb default 11; "
            "tc class add dev %s parent 1: classid 1:1 htb rate %dkbit",
            g_config.lan_iface, g_config.lan_iface, g_config.lan_iface, kbps);
    } else {
        snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s root 2>/dev/null", g_config.lan_iface);
    }
#endif
    system(cmd);
    printf("[+] Bandwidth for %s set to: %s\n", client->ip, kbps > 0 ? "Throttled" : "Unlimited");
}

void display_dashboard(void) {
    system(
#ifdef _WIN32
        "cls"
#else
        "clear"
#endif
    );

    printf("=========================================================================================\n");
    printf("                                  LIVE ROUTER DASHBOARD                                  \n");
    printf("=========================================================================================\n");
    printf(" Mode: %-18s | WAN: %-12s | Sharing Adapter: %s\n",
           g_config.mode == MODE_WIFI_AP ? "USB/Wi-Fi AP" : "USB-to-LAN Gateway",
           g_config.wan_iface, g_config.lan_iface);
    if (g_config.mode == MODE_WIFI_AP) {
        printf(" SSID: %-18s | Password: %s\n", g_config.ssid, g_config.password);
    }
    printf("=========================================================================================\n");
    printf("%-3s | %-15s | %-17s | %-10s | %-15s | %-12s\n",
           "ID", "IP Address", "MAC Address", "Status", "Time Left", "Bandwidth");
    printf("-----------------------------------------------------------------------------------------\n");

    time_t now = time(NULL);
    for (int i = 0; i < g_client_count; i++) {
        Client *c = &g_clients[i];
        if (!c->active) continue;

        char time_str[32] = "Unlimited";
        if (c->time_limit_sec > 0 && !c->blocked) {
            double elapsed = difftime(now, c->first_seen);
            int remaining = c->time_limit_sec - (int)elapsed;
            if (remaining > 0) {
                snprintf(time_str, sizeof(time_str), "%dm %ds", remaining / 60, remaining % 60);
            } else {
                snprintf(time_str, sizeof(time_str), "EXPIRED");
            }
        }

        char bw_str[32];
        if (c->bandwidth_kbps > 0) {
            snprintf(bw_str, sizeof(bw_str), "%d Kbps", c->bandwidth_kbps);
        } else {
            snprintf(bw_str, sizeof(bw_str), "Unlimited");
        }

        printf("%-3d | %-15s | %-17s | %-10s | %-15s | %-12s\n",
               i, c->ip, c->mac,
               c->blocked ? "[BLOCKED]" : "[ONLINE]",
               time_str, bw_str);
    }
    if (g_client_count == 0) {
        printf("                    No connected client devices detected yet.                            \n");
    }
    printf("=========================================================================================\n");
}

void scan_network_clients(void) {
#ifdef _WIN32
    PMIB_IPNETTABLE pIpNetTable = NULL;
    DWORD dwSize = 0;

    if (GetIpNetTable(NULL, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        pIpNetTable = (PMIB_IPNETTABLE)malloc(dwSize);
    }

    if (pIpNetTable && GetIpNetTable(pIpNetTable, &dwSize, FALSE) == NO_ERROR) {
        for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
            MIB_IPNETROW row = pIpNetTable->table[i];

            if (is_valid_unicast_host(row.bPhysAddr, row.dwAddr)) {
                struct in_addr ip_struct;
                ip_struct.s_addr = row.dwAddr;
                char *ip_str = inet_ntoa(ip_struct);
                
                char mac_str[18];
                snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                         row.bPhysAddr[0], row.bPhysAddr[1], row.bPhysAddr[2],
                         row.bPhysAddr[3], row.bPhysAddr[4], row.bPhysAddr[5]);

                bool found = false;
                for (int j = 0; j < g_client_count; j++) {
                    if (strcmp(g_clients[j].mac, mac_str) == 0) {
                        g_clients[j].active = true;
                        found = true;
                        break;
                    }
                }

                if (!found && g_client_count < MAX_CLIENTS) {
                    strncpy(g_clients[g_client_count].ip, ip_str, 16);
                    strncpy(g_clients[g_client_count].mac, mac_str, 18);
                    g_clients[g_client_count].active = true;
                    g_clients[g_client_count].blocked = false;
                    g_clients[g_client_count].first_seen = time(NULL);
                    g_clients[g_client_count].time_limit_sec = 0;
                    g_clients[g_client_count].bandwidth_kbps = 0;
                    g_client_count++;
                }
            }
        }
    }
    if (pIpNetTable) free(pIpNetTable);
#else
    FILE *arp_file = fopen("/proc/net/arp", "r");
    if (!arp_file) return;

    char buffer[256];
    fgets(buffer, sizeof(buffer), arp_file);

    char ip_addr[64], hw_type[64], flags[64], hw_addr[64], mask[64], device[64];
    while (fgets(buffer, sizeof(buffer), arp_file)) {
        if (sscanf(buffer, "%s %s %s %s %s %s", ip_addr, hw_type, flags, hw_addr, mask, device) == 6) {
            unsigned int mac[6];
            if (sscanf(hw_addr, "%x:%x:%x:%x:%x:%x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
                unsigned char mac_bytes[6] = {mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]};
                struct in_addr ip_struct;
                inet_pton(AF_INET, ip_addr, &ip_struct);

                if (is_valid_unicast_host(mac_bytes, ip_struct.s_addr)) {
                    bool found = false;
                    for (int j = 0; j < g_client_count; j++) {
                        if (strcasecmp(g_clients[j].mac, hw_addr) == 0) {
                            g_clients[j].active = true;
                            found = true;
                            break;
                        }
                    }

                    if (!found && g_client_count < MAX_CLIENTS) {
                        strncpy(g_clients[g_client_count].ip, ip_addr, 16);
                        strncpy(g_clients[g_client_count].mac, hw_addr, 18);
                        g_clients[g_client_count].active = true;
                        g_clients[g_client_count].blocked = false;
                        g_clients[g_client_count].first_seen = time(NULL);
                        g_clients[g_client_count].time_limit_sec = 0;
                        g_clients[g_client_count].bandwidth_kbps = 0;
                        g_client_count++;
                    }
                }
            }
        }
    }
    fclose(arp_file);
#endif
}

bool is_valid_unicast_host(unsigned char *mac, unsigned long ip_addr) {
    if ((mac[0] == 0x00 && mac[1] == 0x00 && mac[2] == 0x00 && mac[3] == 0x00 && mac[4] == 0x00 && mac[5] == 0x00) ||
        (mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF && mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF)) return false;
    if (mac[0] == 0x01 && mac[1] == 0x00 && mac[2] == 0x5E) return false;
    unsigned char first_octet = (unsigned char)(ip_addr & 0xFF);
    if (first_octet >= 224 && first_octet <= 239) return false;
    return true;
}

#ifdef _WIN32
BOOL IsRunAsAdmin(void) {
    BOOL fIsAdmin = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fIsAdmin = Elevation.TokenIsElevated;
        }
    }
    if (hToken) CloseHandle(hToken);
    return fIsAdmin;
}

void ElevatePrivileges(int argc, char *argv[]) {
    if (!IsRunAsAdmin()) {
        char szPath[MAX_PATH];
        GetModuleFileNameA(NULL, szPath, MAX_PATH);

        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.cbSize = sizeof(SHELLEXECUTEINFOA);
        sei.lpVerb = "runas";
        sei.lpFile = szPath;
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;

        if (ShellExecuteExA(&sei)) exit(0);
        else exit(1);
    }
}
#endif