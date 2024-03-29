#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <search.h>
#include <stdbool.h>
#include <ctype.h>


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
#define MAX_ATTEMPTS 3


// Global configuration
struct {
    char* server_ip;
    int server_port;
    char* protocol;
    int udp_timeout;
    int udp_retries;
} config = {0};

char globalDisplayName[MAX_DISPLAY_NAME_LENGTH + 1] = ""; // Display name for the client

// Two possible states for the client
typedef enum {
    CLIENT_READY,
    CLIENT_AWAITING_REPLY
} ClientState;
// Initial state is CLIENT_READY
ClientState client_state = CLIENT_READY;


typedef enum {
    START_STATE,
    AUTH_STATE,
    OPEN_STATE,
    ERROR_STATE,
    END_STATE
} State;


bool isValidUsername(const char* username) {
    size_t length = strlen(username);
    if (length > MAX_USERNAME_LENGTH)
        return false;
    for (size_t i = 0; i < length; i++) {
        if (!isalnum(username[i]) && username[i] != '-')
            return false;
    }
    return true;
}


bool isValidSecret(const char* secret) {
    size_t length = strlen(secret);
    if (length > MAX_SECRET_LENGTH)
        return false;
    for (size_t i = 0; i < length; i++) {
        if (!isalnum(secret[i]) && secret[i] != '-')
            return false;
    }
    return true;
}

bool isValidDisplayName(const char* displayName) {
    size_t length = strlen(displayName);
    if (length > MAX_DISPLAY_NAME_LENGTH) return false;
    for (size_t i = 0; i < length; i++) {
        if (!isprint(displayName[i]) || displayName[i] < 0x21 || displayName[i] > 0x7E)
            return false;
    }
    return true;
}


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

void handle_auth(int sock, const char* message) {
    bool valid = true;
    char username[MAX_USERNAME_LENGTH + 1];
    char secret[MAX_SECRET_LENGTH + 1];
    char displayName[MAX_DISPLAY_NAME_LENGTH + 1];




    if (client_state == CLIENT_AWAITING_REPLY) {
        printf("Please wait for the previous action to complete.\n");
        return;
    }



    int argsFilled = sscanf(message, "/auth %s %s %s", username, secret, displayName);
    if (argsFilled != 3) {
        printf("Error: Incorrect AUTH command format.\n");
        return;
    }

    if (!isValidUsername(username) || !isValidSecret(secret) || !isValidDisplayName(displayName)) {
        printf("Error: Validation failed for one or more fields.\n");
        return;
    }


    strncpy(globalDisplayName, displayName, MAX_DISPLAY_NAME_LENGTH);
    globalDisplayName[MAX_DISPLAY_NAME_LENGTH] = '\0';


    char auth_message[BUFFER_SIZE];
    snprintf(auth_message, BUFFER_SIZE, "AUTH %s AS %s USING %s\r", username, displayName, secret);


    if (send(sock, auth_message, strlen(auth_message), 0) < 0) {
        perror("Error sending AUTH message");
    }

    client_state = CLIENT_AWAITING_REPLY;
    if (client_state == CLIENT_AWAITING_REPLY) {
        printf("Client is awaiting reply\n");
    }

   // printf("Sent AUTH message for user: %s", displayName);
}


void handle_join(int sock, char* message) {
    if (client_state == CLIENT_AWAITING_REPLY) {
        printf("Cannot proceed with JOIN. Awaiting server's reply.\n");
        return;
    }
    char channelID[MAX_CHANNEL_ID_LENGTH + 1];


    if (sscanf(message, "/join %20s", channelID) != 1) {
        printf("ERR: JOIN %s\n", message);
        return;
    }


    char join_message[BUFFER_SIZE];
    snprintf(join_message, BUFFER_SIZE, "JOIN %s AS %s\r", channelID, globalDisplayName);

    client_state = CLIENT_AWAITING_REPLY;

    send(sock, join_message, strlen(join_message), 0);

    printf("Sent JOIN message: %s", join_message);
}


void handle_rename(int sock, char* message) {

    char newDisplayName[MAX_DISPLAY_NAME_LENGTH + 1];
    if (sscanf(message, "/rename %20s", newDisplayName) != 1) {
        printf("ERR: RENAME %s", message);
        return;
    }
    // Copy the new display name to the global variable
    strncpy(globalDisplayName, newDisplayName, MAX_DISPLAY_NAME_LENGTH);
    globalDisplayName[MAX_DISPLAY_NAME_LENGTH] = '\0';

    printf("Your new Name: %s\n", newDisplayName);

}

void handle_bye(int sock, char* message) {

    if (client_state == CLIENT_AWAITING_REPLY) {
        printf("Waiting for server's reply before disconnecting.\n");
        return;
    }

    const char* byeMessage = "BYE\r\n";
    send(sock, byeMessage, strlen(byeMessage), 0);
    printf("Disconnecting from server.");
    close(sock);
    exit(0);
}

void handle_msg(int sock, const char* userMessage) {
    //
    if (client_state == CLIENT_AWAITING_REPLY) {
        printf("Please wait for the previous action to complete.\n");
        return;
    }
    char message[BUFFER_SIZE];
    snprintf(message, BUFFER_SIZE, "MSG FROM %s IS %s\r", globalDisplayName, userMessage);
    send(sock, message, strlen(message), 0);
    printf("%s: %s\n", globalDisplayName, userMessage);
}


void handle_response(char *response, int sock) {
    // Check if the response is a REPLY type with success or failure message
    char type[6]; // Buffer to store the message type
    char status[4]; // Buffer to store the status (OK/NOK)
    char content[BUFFER_SIZE]; // Buffer to store the message content


    if (sscanf(response, "%5s %3s IS %[^\r\n]", type, status, content) == 3) {
        if (strcmp(type, "REPLY") == 0) {
            if (strcmp(status, "OK") == 0) {
                client_state = CLIENT_READY;
                if(client_state == CLIENT_READY){
                    printf("Client is ready\n");
                }
                printf("Success: %s\n", content);
            } else {
                printf("Failure: %s\n", content);
            }
        }
        //
    } else if (strncmp(response, "MSG FROM", 8) == 0) {
        // MSG
        char fromDisplayName[MAX_DISPLAY_NAME_LENGTH + 1];
        if (sscanf(response, "MSG FROM %20s IS %[^\r\n]", fromDisplayName, content) == 2) {
            printf("%s: %s\n", fromDisplayName, content);
        } else {
            printf("Invalid MSG format received.\n");
        }
    } else if (strncmp(response, "ERR", 3) == 0) {
        // ERR
        if (sscanf(response, "ERR FROM %[^\r\n]", content) == 1) {
            fprintf(stderr, "Error: %s\n", content);
        } else {
            fprintf(stderr, "Invalid ERR format received.\n");
        }
    } else if(strncmp(response, "BYE", 3) == 0) {
        // BYE
        printf("Server has disconnected.\n");
        close(sock);
        exit(0);

    } else{
        //
        printf("Unhandled server response: %s\n", response);
    }

       // printf("Server: %s", response);



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
                handle_response(buffer, sock);
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



int Start_state(int sock, struct sockaddr_in* server_addr, socklen_t server_addr_len) {
    bool valid = true;
    char username[MAX_USERNAME_LENGTH + 1];
    char secret[MAX_SECRET_LENGTH + 1];
    char displayName[MAX_DISPLAY_NAME_LENGTH + 1];
    char line[BUFFER_SIZE];

    while(valid == true){
        if (fgets(line, BUFFER_SIZE, stdin) == NULL) {
            printf("Error or end-of-file encountered\n");
            continue;
        }
        line[strcspn(line, "\n")] = 0; // Remove newline character
        if (strcmp(line, "/help") == 0) {
            handle_help();
            continue;
        }

    }

}


void udp_client(char* server_ip, int server_port) {
    int sock;
    struct sockaddr_in server_addr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
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

    State state = START_STATE;
    switch (state) {
        case START_STATE:
            Start_state(sock, &server_addr, sizeof(server_addr));
            break;



    }


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

