#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <search.h>


#define BUFFER_SIZE 1024
#define DEFAULT_SERVER_PORT 4567
#define DEFAULT_UDP_TIMEOUT 250
#define DEFAULT_UDP_RETRIES 3
#define POLL_TIMEOUT 50000
#define MAX_USERNAME_LENGTH 20
#define MAX_SECRET_LENGTH 128
#define MAX_DISPLAY_NAME_LENGTH 20
#define MAX_CHANNEL_ID_LENGTH 20
#define MAX_MESSAGE_ID_SIZE 32


// Global configuration
struct {
    char* server_ip;
    int server_port;
    char* protocol;
    int udp_timeout;
    int udp_retries;
} config = {0};

char globalDisplayName[MAX_DISPLAY_NAME_LENGTH + 1] = ""; // Display name for the client



void print_usage() {
    printf("Usage: chat_client [options]\n");
    printf("Options:\n");
    printf("  -t <tcp|udp>             Transport protocol used for connection\n");
    printf("  -s <IP address|hostname> Server IP or hostname\n");
    printf("  -p <port>                Server port (default: 4567)\n");
    printf("  -d <timeout>             UDP confirmation timeout (ms, default: 250)\n");
    printf("  -r <retries>             Maximum number of UDP retransmissions (default: 3)\n");
    printf("  -h                       Prints this help output and exits\n");
}

void handle_help() {
    printf("Available commands:\n");
    printf("/auth <username> <secret> <displayName> - Authenticate with the server.\n");
    printf("/join <channelID> - Join a chat channel.\n");
    printf("/rename <displayName> - Change your display name.\n");
    printf("/help - Show this help message.\n");
}

void parse_arguments(int argc, char* argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "t:s:p:d:r:h")) != -1) {
        switch (opt) {
            case 't':
                config.protocol = optarg;
                break;
            case 's':
                config.server_ip = optarg;
                break;
            case 'p':
                config.server_port = atoi(optarg);
                break;
            case 'd':
                config.udp_timeout = atoi(optarg);
                break;
            case 'r':
                config.udp_retries = atoi(optarg);
                break;
            case 'h':
                print_usage();
                exit(EXIT_SUCCESS);
            default: /* '?' */
                print_usage();
                exit(EXIT_FAILURE);
        }
    }

    if (strcmp(config.protocol, "tcp") == 0) {
        //
    } else if (strcmp(config.protocol, "udp") == 0) {
        //
    } else {
        fprintf(stderr, "Error: bad protocol\n");
        exit(EXIT_FAILURE);
    }
}

void handle_auth(int sock, char* message) {

    char username[MAX_USERNAME_LENGTH + 1];
    char secret[MAX_SECRET_LENGTH + 1];
    char displayName[MAX_DISPLAY_NAME_LENGTH + 1];


    int argsFilled = sscanf(message, "/auth %20s %128s %20s", username, secret, displayName);


    if (argsFilled != 3) {
        printf("ERR: AUTH %s\n", message);
        return;
    }

    strncpy(globalDisplayName, displayName, MAX_DISPLAY_NAME_LENGTH);
    globalDisplayName[MAX_DISPLAY_NAME_LENGTH] = '\0';

    printf("Your name: %s\n", displayName);

    send(sock, message, strlen(message), 0);

}

void handle_join(int sock, char* message) {
    // Send JOIN command to the server
    char channelID[MAX_CHANNEL_ID_LENGTH + 1];
    if (sscanf(message, "/join %20s", channelID) != 1) {
        printf("ERR: JOIN %s\n", message);
        return;
    }

    send(sock, message, strlen(message), 0);
}

void handle_rename(int sock, char* message) {

    // Send RENAME command to the server
    char displayName[MAX_DISPLAY_NAME_LENGTH + 1];
    if (sscanf(message, "/rename %20s", displayName) != 1) {
        printf("ERR: RENAME %s\n", message);
        return;
    }
    strncpy(globalDisplayName, displayName, MAX_DISPLAY_NAME_LENGTH);
    globalDisplayName[MAX_DISPLAY_NAME_LENGTH] = '\0';
    printf("New DisplayName: %s\n", displayName);

    send(sock, message, strlen(message), 0);
}

void handle_bye(int sock, char* message) {
    const char* byeMessage = "BYE\r\n";
    send(sock, byeMessage, strlen(byeMessage), 0);
    printf("Disconnecting from server.\n");
    close(sock);
    exit(0);
}

void handle_msg(int sock, char* message) {
    // Send message to the server
    printf("%s: %s\n", globalDisplayName, message);
    send(sock, message, strlen(message), 0);
}

void handle_response(char *response) {
    if (strncmp(response, "OK", 2) == 0) {
        printf("Success\n");
    } else if (strncmp(response, "NO", 2) == 0) {
        printf("Failure\n");
    }else{
        printf("Server: %s", response);
    }


}


void tcp_client() {
    int sock;
    struct sockaddr_in server_addr;
    struct pollfd fds[2]; // Polling file descriptors

    // Create and connect the socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config.server_port);
    server_addr.sin_addr.s_addr = inet_addr(config.server_ip);

    // Connect to the server
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
    printf("Connected to the server.\n");

    // Initialize pollfd for the connected socket
    fds[0].fd = sock;
    fds[0].events = POLLIN;
    fds[1].fd = STDIN_FILENO; // Standard input
    fds[1].events = POLLIN; // Check for normal data

    while (1) {

        // Wait for server response
        int ret = poll(fds, 2, POLL_TIMEOUT);
        if (ret > 0) {
            if (fds[0].revents & POLLIN) {
                char buffer[BUFFER_SIZE] = {0};
                int bytes_received = recv(sock, buffer, sizeof(buffer), 0);
                if (bytes_received <= 0) {
                    printf("Server error\n");
                    break;
                }
                buffer[bytes_received] = '\0';
                //printf("server: %s", buffer);
                handle_response(buffer);
            }
            if (fds[1].revents & POLLIN) {
                char message[BUFFER_SIZE] = {0};


                if (fgets(message, BUFFER_SIZE, stdin) == NULL) {
                    printf("Error or end-of-file encountered\n");
                    break;
                }
                message[strcspn(message, "\n")] = 0; // Remove newline character


                // Check for commands
                if (strncmp(message, "/auth ", 6) == 0) {
                    handle_auth(sock, message); // Send AUTH command to the server
                } else if (strncmp(message, "/join ", 6) == 0) {
                    handle_join(sock, message); //  Send JOIN command to the server
                } else if (strncmp(message, "/rename ", 8) == 0) {
                    handle_rename(sock, message); // Send RENAME command to the server
                } else if (strncmp(message, "/help", 5) == 0) {
                    handle_help();
                    continue; // Don't wait for server response to /help
                } else if (strncmp(message, "/bye", 4) == 0){
                    handle_bye(sock, message);

                }

                else {
                    // Regular message, send it to the server
                    handle_msg(sock, message);
                }
            }
        } else if (ret == 0) {
            printf("No response from server (timeout).\n");
        } else {
            perror("poll error");
            break;
        }
    }

    close(sock);
}







void init_message_ids_table() {
    hcreate(512); // Create a hash table with 512 buckets
}


int check_and_update_message_id(const char* message_id) {
    ENTRY e, *ep;
    e.key = strdup(message_id);
    e.data = (void*)1;

    ep = hsearch(e, FIND); // Find the message ID in the hash table
    if (ep) {
        free(e.key);
        return 0;
    } else {
        hsearch(e, ENTER);
        return 1;
    }
}


void udp_client(char* server_ip, int server_port) {
    int sock;
    struct sockaddr_in server_addr, from_addr;
    socklen_t from_addr_len = sizeof(from_addr);
    struct pollfd fds[2];

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    fds[0].fd = sock;
    fds[0].events = POLLIN;
    fds[1].fd = STDIN_FILENO;
    fds[1].events = POLLIN;

    while (1) {
        int ret = poll(fds, 2, POLL_TIMEOUT);
        if (ret > 0) {
            if (fds[0].revents & POLLIN) {
                char buffer[BUFFER_SIZE] = {0};
                int bytes_received = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&from_addr, &from_addr_len);
                if (bytes_received <= 0) {
                    printf("Server error or connection closed\n");
                    break;
                }
                char message_id[MAX_MESSAGE_ID_SIZE];
                buffer[bytes_received] = '\0'; // Null-terminate the received data
                printf("Server: %s\n", buffer);
            }
            if (fds[1].revents & POLLIN) {
                char message[BUFFER_SIZE] = {0};
                if (fgets(message, BUFFER_SIZE, stdin) == NULL) {
                    printf("Error or end-of-file encountered\n");
                    continue; // Use 'continue' instead of 'break' to stay in the loop
                }
                message[strcspn(message, "\n")] = 0;
                // Use server_addr for sending as it contains the correct server address and port
                sendto(sock, message, strlen(message), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));

            }
        } else if (ret == 0) {
            printf("No response from server (timeout).\n");
        } else {
            perror("poll error");
            break;
        }
    }

    close(sock);
}

int main(int argc, char *argv[]){
    //
    parse_arguments(argc, argv);
    //


    if (config.server_port != DEFAULT_SERVER_PORT){
        fprintf(stderr, "Error: bad port\n");
        exit(EXIT_FAILURE);
    }else{
        printf("Chosen port: %d\n", config.server_port);
    }
    //
    if (config.server_ip == NULL || strcmp(config.server_ip, "") == 0) {
        fprintf(stderr, "Error: bad IP\n");
        exit(EXIT_FAILURE);
    } else {
        printf("Chosen IP: %s\n", config.server_ip);
    }

    // Check protocol
    if (strcmp(config.protocol, "tcp") == 0) {
        printf("Chosen protocol: %s\n", config.protocol);
        tcp_client();
        //
    } else if (strcmp(config.protocol, "udp") == 0) {
        printf("Chosen protocol: %s\n", config.protocol);
        udp_client(config.server_ip, config.server_port);
        //
    } else {
        fprintf(stderr, "Error: bad protocol\n");
        exit(EXIT_FAILURE);
    }



}

