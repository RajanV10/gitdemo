#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/shell/shell.h>
 
// Custom libraries
#include "wifi.h"
#include "rsa.h"
 
// WiFi settings
#define WIFI_SSID "WhirlpoolZCore"
#define WIFI_PSK "WhirlpoolZCore"
 
// TCP Server settings
#define TCP_PORT 8080
#define MAX_CLIENTS 5
#define BUFFER_SIZE 1024
 
// Global variables for server-to-client communication
static int current_client_socket = -1;
static bool client_connected = false;
static char client_info[64] = "No client connected";
 
// Shell command: send message to client
static int cmd_send_to_client(const struct shell *shell, size_t argc, char **argv)
{
 
    if (!client_connected || current_client_socket < 0) {
        shell_print(shell, "No client connected");
        return -1;
    }
   
    if (argc < 2) {
        shell_print(shell, "Usage: send <message>");
        shell_print(shell, "Example: send Hello from server!");
        return -1;
    }
    // Combine all arguments into one message
    char message[BUFFER_SIZE];
    memset(message, 0, BUFFER_SIZE);
    int offset = 0;
 
    for (size_t i = 1; i < argc && offset < (BUFFER_SIZE - 10); i++) {
        if (i > 1 && offset < (BUFFER_SIZE - 10)) {
            message[offset++] = ' ';
        }
       
        int arg_len = strlen(argv[i]);
        if (offset + arg_len < (BUFFER_SIZE - 10)) {
            strncpy(message + offset, argv[i], arg_len);
            offset += arg_len;
        }
    }
   
    // Add server prefix and terminators
    char full_msg[BUFFER_SIZE];
    snprintf(full_msg, sizeof(full_msg), "[Server]: %s\r\n", message);
 
    int bytes_sent = zsock_send(current_client_socket, full_msg, strlen(full_msg), 0);
    if (bytes_sent > 0) {
        shell_print(shell, "Sent to client: %s", full_msg);
    } else {
        shell_print(shell, "Failed to send message: %d", errno);
    }
   
    return 0;
}
 
// Shell command: show client status
static int cmd_client_status(const struct shell *shell, size_t argc, char **argv)
{
    shell_print(shell, "=== Server Status ===");
    shell_print(shell, "Client connected: %s", client_connected ? "Yes" : "No");
    shell_print(shell, "Client info: %s", client_info);
    shell_print(shell, "Socket: %d", current_client_socket);
    return 0;
}

// Shell command: show RSA public key
static int cmd_show_pubkey(const struct shell *shell, size_t argc, char **argv)
{
    char *pub_key = get_public_key_string_lazy();
    shell_print(shell, "%s", pub_key);
    return 0;
}

// Shell command: show RSA status
static int cmd_rsa_status(const struct shell *shell, size_t argc, char **argv)
{
    shell_print(shell, "RSA Status: %s", is_rsa_initialized() ? "Initialized" : "Not Initialized");
    return 0;
}

// Shell command: manually initialize RSA
static int cmd_rsa_init(const struct shell *shell, size_t argc, char **argv)
{
    if (is_rsa_initialized()) {
        shell_print(shell, "RSA already initialized");
        return 0;
    }
    
    shell_print(shell, "Initializing RSA cryptography...");
    server_crypto_init();
    shell_print(shell, "RSA initialization complete");
    return 0;
}

// Shell command: test DH decryption (for testing purposes)
static int cmd_test_decrypt(const struct shell *shell, size_t argc, char **argv)
{
    if (argc < 2) {
        shell_print(shell, "Usage: testdecrypt <encrypted_hex>");
        return -1;
    }
    
    if (!is_rsa_initialized()) {
        shell_print(shell, "RSA not initialized. Run 'server rsainit' first.");
        return -1;
    }
    
    unsigned char decrypted_buffer[256]; // store decrypted DH key
    size_t decrypted_len = sizeof(decrypted_buffer);
    
    int ret = server_decrypt_client_dh_key(argv[1], decrypted_buffer, &decrypted_len);
    if (ret == 0) {
        shell_print(shell, "Decryption successful (%zu bytes)", decrypted_len);
        shell_print(shell, "Decrypted DH key (hex):");
        for (size_t i = 0; i < decrypted_len; i++) {
            shell_fprintf(shell, SHELL_NORMAL, "%02x", decrypted_buffer[i]); // Print each byte in hex format
        }
        shell_print(shell, "");
        
        // Test shared secret generation
        unsigned char shared_secret[256];
        size_t secret_len = sizeof(shared_secret);
        ret = server_generate_shared_secret(decrypted_buffer, decrypted_len, shared_secret, &secret_len);
        if (ret == 0) {
            shell_print(shell, "Shared secret generated successfully (%zu bytes)", secret_len);
        } else {
            shell_print(shell, "Failed to generate shared secret: %d", ret);
        }
    } else {
        shell_print(shell, "Decryption failed: %d", ret);
    }
    
    return 0;
}
 
// Shell command: disconnect client
static int cmd_disconnect_client(const struct shell *shell, size_t argc, char **argv)
{
    if (!client_connected || current_client_socket < 0) {
        shell_print(shell, "No client connected");
        return -1;
    }
   
    const char *bye_msg = "[Server]: Server is disconnecting you. Goodbye!\r\n";
    zsock_send(current_client_socket, bye_msg, strlen(bye_msg), 0);
   
    zsock_close(current_client_socket);
    current_client_socket = -1;
    client_connected = false;
    strcpy(client_info, "No client connected");
   
    shell_print(shell, "Client disconnected");
    return 0;
}
 
// Define shell commands
SHELL_STATIC_SUBCMD_SET_CREATE(server_cmds,
    SHELL_CMD(send, NULL, "Send message to client", cmd_send_to_client),
    SHELL_CMD(status, NULL, "Show client status", cmd_client_status),
    SHELL_CMD(disconnect, NULL, "Disconnect current client", cmd_disconnect_client),
    SHELL_CMD(pubkey, NULL, "Show RSA public key", cmd_show_pubkey),
    SHELL_CMD(rsastatus, NULL, "Show RSA initialization status", cmd_rsa_status),
    SHELL_CMD(rsainit, NULL, "Manually initialize RSA", cmd_rsa_init),
    SHELL_CMD(testdecrypt, NULL, "Test DH key decryption", cmd_test_decrypt),
    SHELL_SUBCMD_SET_END
);
SHELL_CMD_REGISTER(server, &server_cmds, "TCP server commands", NULL);
 
// Function to handle a single client connection
void handle_client(int client_sock)
{
    int client_sock_id = client_sock;
    char buffer[BUFFER_SIZE];
    int bytes_received;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char client_ip[INET_ADDRSTRLEN];
 
    // Update global variables
    current_client_socket = client_sock_id;
    client_connected = true;
 
    // Get client information
    if (zsock_getpeername(client_sock_id, (struct sockaddr *)&client_addr, &client_addr_len) == 0) {
        zsock_inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        snprintf(client_info, sizeof(client_info), "%s:%d", client_ip, ntohs(client_addr.sin_port));
        printk("TCP Server: Client connected from %s\r\n", client_info);
    } else {
        strcpy(client_info, "Unknown address");
        printk("TCP Server: Client connected (unable to get address)\r\n");
    }
 
    // Send welcome message
    const char *welcome_msg = "Welcome to ESP32-C3 TCP Server! 2-way communication enabled.\r\n";
    zsock_send(client_sock_id, welcome_msg, strlen(welcome_msg), 0);
   
    printk("\n=== 2-WAY COMMUNICATION READY ===\r\n");
    printk("You can now send messages to client using:\r\n");
    printk("  server send <your_message>\r\n");
    printk("  server status\r\n");
    printk("  server disconnect\r\n");
    printk("================================\r\n\n");
 
    // Handle client communication
    while (1) {
        // Clear buffer
        memset(buffer, 0, BUFFER_SIZE);
 
        // Receive data from client
        bytes_received = zsock_recv(client_sock_id, buffer, BUFFER_SIZE - 1, 0);
       
        if (bytes_received < 0) {
            if (errno == EAGAIN) {
                // No data available, continue
                k_msleep(100);
                continue;
            } else {
                printk("TCP Server: Receive error: %d\r\n", errno);
                break;
            }
        } else if (bytes_received == 0) {
            printk("TCP Server: Client disconnected\r\n");
            break;
        }
 
        // Null-terminate the received data
        buffer[bytes_received] = '\0';
       
        // Remove trailing newline/carriage return
        if (buffer[bytes_received - 1] == '\n' || buffer[bytes_received - 1] == '\r') {
            buffer[bytes_received - 1] = '\0';
            if (bytes_received > 1 && (buffer[bytes_received - 2] == '\n' || buffer[bytes_received - 2] == '\r')) {
                buffer[bytes_received - 2] = '\0';
            }
        }
 
        printk("TCP Server: Received from client: '%s'\r\n", buffer);
 
        // Process client commands and send responses
        if (strcmp(buffer, "status") == 0) {
            const char *status_msg = "TCP Server Status:\r\n"
                                     "  Server: Running\r\n"
                                     "  Port: 8080\r\n"
                                     "  WiFi: Connected\r\n"
                                     "  Board: ESP32-C3\r\n\r\n";
            zsock_send(client_sock_id, status_msg, strlen(status_msg), 0);
            printk("TCP Server: Sent status response\r\n");
        } else if (strcmp(buffer, "help") == 0) {
            const char *help_msg = "Available Commands:\r\n"
                                  "  status     - Show server status\r\n"
                                  "  hello      - Get greeting message\r\n"
                                  "  pubkey     - Get RSA public key (generates on first request)\r\n"
                                  "  getpubkey  - Get RSA public key (alias)\r\n"
                                  "  help       - Show this help message\r\n"
                                  "  exit/quit  - Disconnect from server\r\n"
                                  "\r\n"
                                  "Automatic Commands (handled by client):\r\n"
                                  "  ENCRYPTED_DH_PUBKEY:<hex> - Encrypted DH public key exchange\r\n\r\n";
            zsock_send(client_sock_id, help_msg, strlen(help_msg), 0);
            printk("TCP Server: Sent help response\r\n");
        } else if (strcmp(buffer, "hello") == 0) {
            const char *hello_msg = "Hello from TCP Server!\r\n";
            zsock_send(client_sock_id, hello_msg, strlen(hello_msg), 0);
            printk("TCP Server: Sent hello response\r\n");
        } else if (strcmp(buffer, "pubkey") == 0 || strcmp(buffer, "getpubkey") == 0) {
            // Send RSA public key to client (with lazy initialization)
            printk("TCP Server: Client requested RSA public key\r\n");
            char *pub_key = get_public_key_string_lazy(); // lazy means it initializes RSA Cryptography only if not already done
            zsock_send(client_sock_id, pub_key, strlen(pub_key), 0);
            printk("TCP Server: Sent RSA public key to client\r\n");
        } else if (strncmp(buffer, "ENCRYPTED_DH_PUBKEY:", 20) == 0) {
            // Handle encrypted DH public key from client
            printk("TCP Server: Received encrypted DH public key from client\r\n");
            
            const char *encrypted_hex = buffer + 20; // Skip "ENCRYPTED_DH_PUBKEY:" prefix
            unsigned char decrypted_dh_key[256];
            size_t decrypted_len = sizeof(decrypted_dh_key);
            
            // Decrypt the client's DH public key
            int ret = server_decrypt_client_dh_key(encrypted_hex, decrypted_dh_key, &decrypted_len);
            if (ret == 0) {
                printk("Successfully decrypted client DH public key\r\n");
                
                // First, ensure server has generated its DH key pair
                unsigned char temp_dh_key[256];
                size_t temp_dh_len = sizeof(temp_dh_key);
                ret = server_get_dh_pubkey(temp_dh_key, &temp_dh_len);
                if (ret != 0) {
                    printk("ERROR: Failed to generate server DH key pair: %d\r\n", ret);
                } else {
                    printk("Server DH key pair ready for shared secret calculation\r\n");
                    
                    // Now generate the shared secret using the same DH private key
                    unsigned char shared_secret[256];
                    size_t secret_len = sizeof(shared_secret);
                    ret = server_generate_shared_secret(decrypted_dh_key, decrypted_len, 
                                                      shared_secret, &secret_len);
                    if (ret == 0) {
                        printk("=== DH KEY EXCHANGE COMPLETE (SERVER SIDE) ===\r\n");
                        printk("Shared secret established on server side!\r\n");
                        printk("Shared secret length: %zu bytes\r\n", secret_len);
                        
                        // Send our DH public key to client (reusing the same key pair)
                        ret = server_send_dh_pubkey(client_sock_id);
                        if (ret == 0) {
                            printk("Successfully sent server DH public key to client\r\n");
                            
                            // Send success confirmation to client
                            const char *success_msg = "DH_KEY_EXCHANGE_SUCCESS: Server shared secret ready. Check your shared secret!\r\n";
                            zsock_send(client_sock_id, success_msg, strlen(success_msg), 0);
                            printk("TCP Server: Sent DH success confirmation to client\r\n");
                        } else {
                            printk("ERROR: Failed to send server DH public key\r\n");
                            const char *error_msg = "DH_KEY_EXCHANGE_ERROR: Failed to send server DH key\r\n";
                            zsock_send(client_sock_id, error_msg, strlen(error_msg), 0);
                        }
                    } else {
                        printk("ERROR: Failed to generate shared secret\r\n");
                        const char *error_msg = "DH_KEY_EXCHANGE_ERROR: Failed to generate shared secret\r\n";
                        zsock_send(client_sock_id, error_msg, strlen(error_msg), 0);
                    }
                }
            } else {
                printk("ERROR: Failed to decrypt client DH public key\r\n");
                const char *error_msg = "DH_KEY_EXCHANGE_ERROR: Failed to decrypt DH key\r\n";
                zsock_send(client_sock_id, error_msg, strlen(error_msg), 0);
            }
        } else if (strcmp(buffer, "exit") == 0 || strcmp(buffer, "quit") == 0) {
            const char *bye_msg = "Goodbye from TCP Server!\r\n";
            zsock_send(client_sock_id, bye_msg, strlen(bye_msg), 0);
            printk("TCP Server: Client requested disconnect\r\n");
            break;
        } else {
            // Echo the message back with a prefix
            char echo_msg[BUFFER_SIZE + 50];
            snprintf(echo_msg, sizeof(echo_msg), "[Client Echo]: %s\r\n", buffer);
            int bytes_sent = zsock_send(client_sock_id, echo_msg, strlen(echo_msg), 0);
            printk("TCP Server: Sent echo response (%d bytes): %s", bytes_sent, echo_msg);
        }
    }
 
    // Clean up when client disconnects
    current_client_socket = -1;
    client_connected = false;
    strcpy(client_info, "No client connected");
   
    // Close client socket
    zsock_close(client_sock_id);
    printk("TCP Server: Client connection closed\r\n");
    printk("Server ready for next client connection...\r\n");
}
 
// TCP server thread function
void tcp_server_thread_func(void *arg1, void *arg2, void *arg3)
{
    int server_sock;
    int client_sock;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len;
    int opt = 1;
 
    printk("TCP Server: Starting TCP server on port %d\r\n", TCP_PORT);
 
    // Create socket
    server_sock = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_sock < 0) {
        printk("TCP Server: Failed to create socket: %d\r\n", errno);
        return;
    }
 
    // Set socket options
    if (zsock_setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        printk("TCP Server: Failed to set socket options: %d\r\n", errno);
        zsock_close(server_sock);
        return;
    }
 
    // Setup server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(TCP_PORT);
 
    // Bind socket
    if (zsock_bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printk("TCP Server: Failed to bind socket: %d\r\n", errno);
        zsock_close(server_sock);
        return;
    }
 
    // Listen for connections
    if (zsock_listen(server_sock, MAX_CLIENTS) < 0) {
        printk("TCP Server: Failed to listen: %d\r\n", errno);
        zsock_close(server_sock);
        return;
    }
 
    printk("TCP Server: Server listening on port %d\r\n", TCP_PORT);
    printk("TCP Server: Waiting for client connections...\r\n");
 
    // Accept client connections
    while (1) {
        client_addr_len = sizeof(client_addr);
        client_sock = zsock_accept(server_sock, (struct sockaddr *)&client_addr, &client_addr_len);
       
        if (client_sock < 0) {
            printk("TCP Server: Failed to accept connection: %d\r\n", errno);
            continue;
        }
 
        // Handle the client directly (blocking, one at a time)
        handle_client(client_sock);
    }
 
    // Close server socket (should never reach here)
    zsock_close(server_sock);
}
 
int main(void)
{
    int ret;
 
    printk("=== TCP Server Demo ===\r\n");
    printk("Starting WiFi connection and TCP server...\r\n");
 
    // Give the system some time to initialize
    k_msleep(2000);
 
    // Initialize WiFi
    printk("Initializing WiFi...\r\n");
    wifi_init();
    
    // Give WiFi subsystem time to initialize
    k_msleep(1000);
 
    // Connect to the WiFi network (blocking)
    printk("Connecting to WiFi SSID: %s\r\n", WIFI_SSID);
    ret = wifi_connect(WIFI_SSID, WIFI_PSK);
    if (ret < 0) {
        printk("Error (%d): WiFi connection failed\r\n", ret);
        return 0;
    }
 
    // Wait to receive an IP address (blocking)
    printk("Waiting for IP address...\r\n");
    wifi_wait_for_ip_addr();
    printk("IP address obtained successfully!\r\n");
 
    // Print connection information
    printk("=== WiFi Connection Successful ===\r\n");
    printk("Connected to: %s\r\n", WIFI_SSID);
    printk("IP obtained via DHCP (see logs above)\r\n");
   
    printk("Starting TCP server on port %d...\r\n", TCP_PORT);
 
   
 
    // Run TCP server directly in main thread
    tcp_server_thread_func(NULL, NULL, NULL);
    
    return 0;
}