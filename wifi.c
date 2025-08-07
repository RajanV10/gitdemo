#include <string.h>
#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/socket.h>

// Event callbacks
static struct net_mgmt_event_callback wifi_cb;
static struct net_mgmt_event_callback ipv4_cb;

// Semaphores
static K_SEM_DEFINE(sem_wifi, 0, 1);
static K_SEM_DEFINE(sem_ipv4, 0, 1);

// Called when the WiFi is connected
static void on_wifi_connection_event(struct net_mgmt_event_callback *cb,
                                     uint32_t mgmt_event,
                                     struct net_if *iface)
{
    if (mgmt_event == NET_EVENT_WIFI_CONNECT_RESULT) {
        printk("WiFi event: Connect result received\r\n");
        k_sem_give(&sem_wifi);
    } else if (mgmt_event == NET_EVENT_WIFI_DISCONNECT_RESULT) {
        printk("WiFi event: Disconnected\r\n");
        k_sem_take(&sem_wifi, K_NO_WAIT);
    }
}

// Global variable to store the DHCP IP address
static char dhcp_ip_address[16] = "0.0.0.0";

// Event handler for WiFi management events
static void on_ipv4_obtained(struct net_mgmt_event_callback *cb,
                             uint32_t mgmt_event,
                             struct net_if *iface)
{
    // Signal that the IP address has been obtained
    if (mgmt_event == NET_EVENT_IPV4_ADDR_ADD) {
        printk("DHCP event: IPv4 address obtained\r\n");
        
        // Try to capture the IP address from the interface
        struct net_if_addr *if_addr = net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED);
        if (if_addr) {
            net_addr_ntop(AF_INET, &if_addr->address.in_addr, dhcp_ip_address, sizeof(dhcp_ip_address));
            printk("DHCP: Captured IP address: %s\r\n", dhcp_ip_address);
        }
        
        k_sem_give(&sem_ipv4);
    }
}

// Initialize the WiFi event callbacks
void wifi_init(void)
{
    struct net_if *iface;
    
    printk("WiFi init: Starting WiFi initialization\r\n");
    
    // Get the default interface first to check if it exists
    iface = net_if_get_default();
    if (!iface) {
        printk("WiFi init: No default network interface found\r\n");
        return;
    }
    
    printk("WiFi init: Default interface found: %p\r\n", iface);
    
    // Initialize the event callbacks
    net_mgmt_init_event_callback(&wifi_cb,
                                 on_wifi_connection_event,
                                 NET_EVENT_WIFI_CONNECT_RESULT | NET_EVENT_WIFI_DISCONNECT_RESULT);
    net_mgmt_init_event_callback(&ipv4_cb,
                                 on_ipv4_obtained,
                                 NET_EVENT_IPV4_ADDR_ADD);
    
    // Add the event callbacks
    net_mgmt_add_event_callback(&wifi_cb);
    net_mgmt_add_event_callback(&ipv4_cb);
    
    printk("WiFi init: Event callbacks registered\r\n");
}

// Connect to the WiFi network (blocking)
int wifi_connect(char *ssid, char *psk)
{
    int ret;
    struct net_if *iface;
    struct wifi_connect_req_params params;

    printk("WiFi connect: Attempting to connect to SSID: %s\r\n", ssid);

    // Get the default networking interface
    iface = net_if_get_default();
    if (!iface) {
        printk("Error: No default network interface found\r\n");
        return -1;
    }
    
    printk("WiFi connect: Default interface found: %p\r\n", iface);
    
    // Check if the interface is up
    if (!net_if_is_up(iface)) {
        printk("WiFi connect: Interface is down, bringing it up...\r\n");
        net_if_up(iface);
        k_msleep(1000);  // Give it time to come up
    }
    
    printk("WiFi connect: Interface is %s\r\n", net_if_is_up(iface) ? "up" : "down");

    // Fill in the connection request parameters
    params.ssid = (const uint8_t *)ssid;
    params.ssid_length = strlen(ssid);
    
    // Set security type based on PSK length
    if (strlen(psk) == 0) {
        params.security = WIFI_SECURITY_TYPE_NONE;
        params.psk = NULL;
        params.psk_length = 0;
        printk("WiFi connect: Using open security (no PSK)\r\n");
    } else {
        params.security = WIFI_SECURITY_TYPE_PSK;
        params.psk = (const uint8_t *)psk;
        params.psk_length = strlen(psk);
        printk("WiFi connect: Using PSK security\r\n");
    }
    
    params.band = WIFI_FREQ_BAND_UNKNOWN;
    params.channel = WIFI_CHANNEL_ANY;
    
    // Set MFP based on security type
    if (params.security == WIFI_SECURITY_TYPE_NONE) {
        params.mfp = WIFI_MFP_DISABLE;  // Disable MFP for open networks
    } else {
        params.mfp = WIFI_MFP_OPTIONAL;
    }

    // Debug: Print all connection parameters
    printk("WiFi connect: Connection parameters:\r\n");
    printk("  SSID: %.*s (length: %d)\r\n", params.ssid_length, params.ssid, params.ssid_length);
    printk("  Security: %d\r\n", params.security);
    printk("  PSK length: %d\r\n", params.psk_length);
    printk("  Band: %d\r\n", params.band);
    printk("  Channel: %d\r\n", params.channel);
    printk("  MFP: %d\r\n", params.mfp);

    // Connect to the WiFi network
    printk("WiFi connect: Sending connection request...\r\n");
    ret = net_mgmt(NET_REQUEST_WIFI_CONNECT,
                   iface,
                   &params,
                   sizeof(params));
    
    if (ret) {
        printk("WiFi connect: Connection request failed with error %d\r\n", ret);
        return ret;
    }

    // Wait for the connection to complete
    printk("WiFi connect: Waiting for connection to complete...\r\n");
    
    // Wait with timeout
    ret = k_sem_take(&sem_wifi, K_FOREVER);
    if (ret != 0) {
        printk("WiFi connect: Connection failed (error: %d)\r\n", ret);
        return ret;
    }
    
    printk("WiFi connect: Connection completed\r\n");

    return 0;
}

// Wait for IP address (blocking)
void wifi_wait_for_ip_addr(void)
{
    struct wifi_iface_status status;
    struct net_if *iface;

    // Get interface
    iface = net_if_get_default();
    if (!iface) {
        printk("Error: No default network interface found\r\n");
        return;
    }

    // Get the WiFi status
    if (net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS,
                 iface,
                 &status,
                 sizeof(struct wifi_iface_status))) {
        printk("Error: WiFi status request failed\r\n");
        return;
    }

    // Print the WiFi status
    printk("WiFi status:\r\n");
    if (status.state >= WIFI_STATE_ASSOCIATED) {
        printk("  SSID: %-32s\r\n", status.ssid);
        printk("  Band: %s\r\n", wifi_band_txt(status.band));
        printk("  Channel: %d\r\n", status.channel);
        printk("  Security: %s\r\n", wifi_security_txt(status.security));
        printk("  IP address: Successfully obtained\r\n");
    } else {
        printk("  WiFi not connected (state: %d)\r\n", status.state);
    }
}

// Disconnect from the WiFi network
int wifi_disconnect(void)
{
    int ret;
    struct net_if *iface = net_if_get_default();

    ret = net_mgmt(NET_REQUEST_WIFI_DISCONNECT, iface, NULL, 0);

    return ret;
}
