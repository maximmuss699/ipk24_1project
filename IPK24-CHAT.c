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
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>

#define BUFFER_SIZE 1024
#define DEFAULT_SERVER_PORT 4567
#define DEFAULT_UDP_TIMEOUT 250
#define DEFAULT_UDP_RETRIES 3
#define POLL_TIMEOUT 50000
#define MAX_USERNAME_LENGTH 20
#define MAX_SECRET_LENGTH 128
#define MAX_DISPLAY_NAME_LENGTH 20
#define MAX_CHANNEL_ID_LENGTH 20

bool terminateSignalReceived = false;
pthread_mutex_t terminateSignalMutex = PTHREAD_MUTEX_INITIALIZER;


// Global configuration
struct {
    char* server_ip;
    int server_port;
    char* protocol;
    int udp_timeout;
    int udp_retries;
} config = {0};

char globalDisplayName[MAX_DISPLAY_NAME_LENGTH + 1] = ""; // Display name for the client
char globalDisplayNameUDP[MAX_CHANNEL_ID_LENGTH + 1] = "";



typedef enum {
    START_STATE,
    AUTH_STATE,
    OPEN_STATE,
    ERROR_STATE,
    END_STATE
} State;


uint16_t messageID = 0x0000;

bool Check_username(const char* username) {
    size_t length = strlen(username);
    if (length > MAX_USERNAME_LENGTH)
        return false;
    for (size_t i = 0; i < length; i++) {
        if (!isalnum(username[i]) && username[i] != '-')
            return false;
    }
    return true;
}


bool Check_secret(const char* secret) {
    size_t length = strlen(secret);
    if (length > MAX_SECRET_LENGTH)
        return false;
    for (size_t i = 0; i < length; i++) {
        if (!isalnum(secret[i]) && secret[i] != '-')
            return false;
    }
    return true;
}

bool Check_Displayname(const char* displayName) {
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






int handle_response(char *response, int sock, State state) {
    // Check if the response is a REPLY type with success or failure message
    char type[6]; // Buffer to store the message type
    char status[4]; // Buffer to store the status (OK/NOK)
    char content[BUFFER_SIZE]; // Buffer to store the message content
    printf("Response: %d\n", state);
    if (state == AUTH_STATE) {
        printf("Response HANDLE AUTH: %s\n", response);
        if (sscanf(response, "%5s %3s IS %[^\r\n]", type, status, content) == 3) {
            if (strcmp(type, "REPLY") == 0) {
                if (strcmp(status, "OK") == 0) {
                    printf("Success: %s\n", content);
                    return 0;
                } else if (strcmp(status, "NOK") == 0) {
                    printf("Failure: %s\n", content);
                    return 1;

                } else {
                    printf("Unhandled server response: %s\n", response);
                    return 3;
                }
            } else {
                printf("Unhandled server response: %s\n", response);
                return 3;

            }
        } else if (strncmp(response, "ERR", 3) == 0) {
            // ERR
            if (sscanf(response, "ERR FROM %[^\r\n]", content) == 1) {
                fprintf(stderr, "Error: %s\n", content);
                return 2;
            }
        } else {
            printf("Wrong response from the server in Auth state: %s\n", response);
            return 3;
        }
    } else if(state == OPEN_STATE){
        printf("HANDLE OPEN: %s\n", response);
        if (sscanf(response, "%5s %3s IS %[^\r\n]", type, status, content) == 3) {
            if (strcmp(type, "REPLY") == 0) {
                if (strcmp(status, "OK") == 0) {
                    printf("Success: %s\n", content);
                    return 0;
                } else if (strcmp(status, "NOK") == 0) {
                    printf("Failure: %s\n", content);
                    return 1;

                } else {
                    printf("Wrong reply status: %s\n", response);
                    return 3;
                }
            } else {
                printf("Unhandled server response: %s\n", response);
                return 3;

            }
        } else if (strncmp(response, "ERR", 3) == 0) {
            // ERR
            if (sscanf(response, "ERR FROM %[^\r\n]", content) == 1) {
                fprintf(stderr, "Error: %s\n", content);
            }
            return 2;
        } else if(strncmp(response, "BYE", 3) == 0){
            close(sock);
            exit(0);

        }else if(strncmp(response, "MSG FROM", 8) == 0){
            char Server_name[MAX_DISPLAY_NAME_LENGTH + 1];
            if (sscanf(response, "MSG FROM %20s IS %[^\r\n]", Server_name, content) == 2) {
                printf("%s: %s\n", Server_name, content);
            } else {
                printf("Invalid MSG format received.\n");
            }

        }
        else
        {
            printf("Wrong response from the server in OPEN state: %s\n", response);
            return 3;
        }



    }

}

int Start_stateTCP(int sock, struct sockaddr_in* server_addr, socklen_t server_addr_len) {
    char message[BUFFER_SIZE] = {0};
    char auth_message[BUFFER_SIZE];
    char username[MAX_USERNAME_LENGTH + 1];
    char secret[MAX_SECRET_LENGTH + 1];
    char displayName[MAX_DISPLAY_NAME_LENGTH + 1];
    int send_auth = 0;
    while (send_auth == 0) {

        if (fgets(message, BUFFER_SIZE, stdin) == NULL) {
            printf("Error or end-of-file encountered\n");
            break;
        }
        message[strcspn(message, "\n")] = 0; // Remove newline character
        if (message[0] == '\0') {
            printf("Line is empty.\n");
        }else if(strncmp(message, "/help ", 6) == 0){
            handle_help();
        }
        else{
            if (strncmp(message, "/auth ", 6) == 0) {
                int argsFilled = sscanf(message, "/auth %s %s %s", username, secret, displayName);
                if (Check_username(username) == true && Check_secret(secret) == true && Check_Displayname(displayName) == true && argsFilled == 3) {
                    strncpy(globalDisplayName, displayName, MAX_DISPLAY_NAME_LENGTH);
                    globalDisplayName[MAX_DISPLAY_NAME_LENGTH] = '\0';
                    snprintf(auth_message, BUFFER_SIZE, "AUTH %s AS %s USING %s\r", username, displayName, secret);


                    if (send(sock, auth_message, strlen(auth_message), 0) < 0) {
                        perror("Error sending AUTH message");
                    }
                    send_auth = 1;
                    return AUTH_STATE;

                }else{
                    printf("Error: Incorrect AUTH command format.\n");
                }
            } else {
                printf("Please authenticate first.\n");
            }

        }

    }
    return AUTH_STATE;
}

int AUTH_STATETCP(int sock, struct sockaddr_in* server_addr, socklen_t server_addr_len, State state) {
    char message[BUFFER_SIZE] = {0};
    char auth_message[BUFFER_SIZE];
    char username[MAX_USERNAME_LENGTH + 1];
    char secret[MAX_SECRET_LENGTH + 1];
    char displayName[MAX_DISPLAY_NAME_LENGTH + 1];
    struct pollfd fds[2]; // Polling file descriptors
    fds[0].fd = sock;
    fds[0].events = POLLIN;
    fds[1].fd = STDIN_FILENO; // Standard input
    fds[1].events = POLLIN; // Check for normal data
    int auth_state=0;
    int recv_reply = 1;

    while(auth_state == 0){


        pthread_mutex_lock(&terminateSignalMutex);
        if (errno == EINTR && terminateSignalReceived) {
            pthread_mutex_unlock(&terminateSignalMutex);
            return END_STATE;
        }
        pthread_mutex_unlock(&terminateSignalMutex);


        int ret = poll(fds, 2, POLL_TIMEOUT);
        if (ret > 0) {
            if (fds[0].revents & POLLIN) // Server response
            {
                char buffer[BUFFER_SIZE] = {0};
                int bytes_received = recv(sock, buffer, sizeof(buffer), 0);
                if (bytes_received <= 0) {
                    printf("Server error\n");
                    exit(1);
                }
                buffer[bytes_received] = '\0';
                printf("server: %s", buffer);
                int response = handle_response(buffer, sock, state);

                if (response == 0) {
                    auth_state = 1;
                    return OPEN_STATE;
                } else if (response == 1) {
                    recv_reply = 0;
                } else if (response == 2) {
                    auth_state = 1;
                }else if (response == 3){
                    auth_state = 1;
                    return ERROR_STATE;
                }
            }

            if (fds[1].revents & POLLIN && recv_reply == 0) // Stdin
            {
                if (fgets(message, BUFFER_SIZE, stdin) == NULL) {
                    printf("Error or end-of-file encountered\n");
                    break;
                }
                if (feof(stdin)) {
                    auth_state = 1;
                    return END_STATE;
                }
                message[strcspn(message, "\n")] = 0; // Remove newline character


                if (strncmp(message, "/auth ", 6) == 0) {
                    int argsFilled = sscanf(message, "/auth %s %s %s", username, secret, displayName);
                    if (Check_username(username) == true && Check_secret(secret) == true &&
                        Check_Displayname(displayName) == true && argsFilled == 3) {
                        strncpy(globalDisplayName, displayName, MAX_DISPLAY_NAME_LENGTH);
                        globalDisplayName[MAX_DISPLAY_NAME_LENGTH] = '\0';
                        snprintf(auth_message, BUFFER_SIZE, "AUTH %s AS %s USING %s\r", username, displayName,
                                 secret);


                        if (send(sock, auth_message, strlen(auth_message), 0) < 0) {
                            perror("Error sending AUTH message");
                        }
                        recv_reply = 1;

                    } else {
                        printf("Error: Incorrect AUTH command format.\n");
                    }
                } else {
                    if (strncmp(message, "/help ", 6) == 0) {
                        handle_help();
                    }else {
                        printf("Error: Incorrect AUTH command format.\n");
                    }
                }


            }
        }
    }
}


int Open_stateTCP(int sock, struct sockaddr_in* server_addr, socklen_t server_addr_len, State state) {
    char message[BUFFER_SIZE] = {0};
    char auth_message[BUFFER_SIZE];
    char displayName[MAX_DISPLAY_NAME_LENGTH + 1];
    char channelID[MAX_CHANNEL_ID_LENGTH + 1];
    char newDisplayName[MAX_DISPLAY_NAME_LENGTH + 1];
    struct pollfd fds[2]; // Polling file descriptors
    fds[0].fd = sock;
    fds[0].events = POLLIN;
    fds[1].fd = STDIN_FILENO; // Standard input
    fds[1].events = POLLIN; // Check for normal data
    int open_state = 1;
    int recv_reply = 0;
    while (open_state == 1) {

        printf("Replay is %d\n", recv_reply);
        pthread_mutex_lock(&terminateSignalMutex);
        if (errno == EINTR && terminateSignalReceived) {
            pthread_mutex_unlock(&terminateSignalMutex);
            return END_STATE;
        }
        pthread_mutex_unlock(&terminateSignalMutex);

        int ret = poll(fds, 2, POLL_TIMEOUT);
        if (ret > 0) {
            if (fds[0].revents & POLLIN) // Server response
            {
                char buffer[BUFFER_SIZE] = {0};
                int bytes_received = recv(sock, buffer, sizeof(buffer), 0);
                if (bytes_received <= 0) {
                    printf("Server error\n");
                    exit(1);
                }
                buffer[bytes_received] = '\0';
                printf("server: %s", buffer);
                int response = handle_response(buffer, sock, state);

                if (response == 0) {
                    recv_reply = 0;
                } else if (response == 1) {
                    recv_reply = 0;
                } else if (response == 2) {
                    open_state = 0;
                }else if (response == 3){
                    open_state = 1;
                    return ERROR_STATE;
                }

            }
            if (fds[1].revents & POLLIN && recv_reply == 0) // Stdin
            {
                if (fgets(message, BUFFER_SIZE, stdin) == NULL) {
                    printf("Error or end-of-file encountered\n");
                    break;
                }
                if (feof(stdin)) {
                    open_state = 1;
                    return END_STATE;
                }
                message[strcspn(message, "\n")] = 0; // Remove newline character


                if (strncmp(message, "/join ", 6) == 0) {
                    int argsFilled = sscanf(message, "/join %20s", channelID);
                    if (argsFilled == 1 && strlen(channelID) <= MAX_CHANNEL_ID_LENGTH) {

                        char join_message[BUFFER_SIZE];
                        snprintf(join_message, BUFFER_SIZE, "JOIN %s AS %s\r", channelID, globalDisplayName);
                        if (send(sock, join_message, strlen(join_message), 0) < 0) {
                            perror("Error sending JOIN message");
                            open_state = 0;
                            return ERROR_STATE;
                        }

                        recv_reply = 1;
                        printf("Sent JOIN message: %s", join_message);
                    }else{
                        printf("Error: Incorrect JOIN command format.\n");
                    }
                } else if(strncmp(message, "/rename ", 8) == 0){
                    int argsFilled = sscanf(message, "/rename %20s", newDisplayName);
                    if (argsFilled == 1 && Check_Displayname(newDisplayName)) {

                        // Copy the new display name to the global variable
                        strncpy(globalDisplayName, newDisplayName, MAX_DISPLAY_NAME_LENGTH);
                        globalDisplayName[MAX_DISPLAY_NAME_LENGTH] = '\0';

                        printf("Your new Name: %s\n", newDisplayName);
                    }else{
                        printf("Error: Incorrect RENAME command format.\n");
                    }
                }else if (strncmp(message, "/help", 5) == 0) {
                    handle_help();
                }
                else {
                    char msg_message[BUFFER_SIZE];
                    snprintf(msg_message, BUFFER_SIZE, "MSG FROM %s IS %s\r", globalDisplayName, message);
                    if (send(sock, msg_message, strlen(msg_message), 0) < 0) {
                        perror("Error sending MSG message");
                        open_state = 0;
                        return ERROR_STATE;
                    }
                    printf("%s: %s\n", globalDisplayName, message);

                }


            }
        }
    }
}

int Error_stateTCP(int sock, struct sockaddr_in* server_addr, socklen_t server_addr_len) {
    const char* ERRessage = "error\r\n";
    char msg_message[BUFFER_SIZE];
    snprintf(msg_message, BUFFER_SIZE, "ERR FROM %s IS %s\r", globalDisplayName, ERRessage);
    if (send(sock, msg_message, strlen(msg_message), 0) < 0) {
        perror("Error sending BYE message");
        return ERROR_STATE;
    }
    return END_STATE;
}

int End_stateTCP(int sock, struct sockaddr_in* server_addr, socklen_t server_addr_len) {
    const char* byeMessage = "BYE\r\n";
    if (send(sock, byeMessage, strlen(byeMessage), 0) < 0) {
        perror("Error sending ERR");
        return ERROR_STATE;
    }
    printf("Disconnecting from server.");
    close(sock);
    exit(EXIT_FAILURE);

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
    if (connect(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
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
    State state = START_STATE;

    while (1) {

        switch (state) {
            case START_STATE:
                printf(("Start state\n"));
                state = Start_stateTCP(sock, &server_addr, sizeof(server_addr));
                break;
            case AUTH_STATE:
                printf("Auth state\n");
                state = AUTH_STATETCP(sock, &server_addr, sizeof(server_addr), state);
                break;
            case OPEN_STATE:
                printf("Open state\n");
                state = Open_stateTCP(sock, &server_addr, sizeof(server_addr), state);
                break;
            case ERROR_STATE:
                printf("Error state\n");
                state = Error_stateTCP(sock, &server_addr, sizeof(server_addr));
                break;
            case END_STATE:
                printf("End state\n");
                state = End_stateTCP(sock, &server_addr, sizeof(server_addr));
                break;
            default:
                perror("Invalid state");
                exit(EXIT_FAILURE);
        }

    }
    close(sock);
    exit(EXIT_SUCCESS);
}

void signalHandler(int signal) {
    if (signal == SIGINT) {
        pthread_mutex_lock(&terminateSignalMutex);
        terminateSignalReceived = true;
        pthread_mutex_unlock(&terminateSignalMutex);
    }
}

void print_hex(const char* message, int len) {
    for (int i = 0; i < len; ++i) {
        printf("%02x ", (unsigned char)message[i]);
    }
    printf("\n");
}


int wait_confirm(int sockfd, const char* message, size_t message_size, struct sockaddr* address, socklen_t address_size, int flags, uint16_t timeout, uint8_t retry, uint16_t expectedMessageID) {
    int attempts = 0;
    int confirmed = 0;
    struct pollfd fds[1];
    fds[0].fd = sockfd;
    fds[0].events = POLLIN;

    // set non-blocking mode
    int current_flags = fcntl(sockfd, F_GETFL, 0);
    if (fcntl(sockfd, F_SETFL, current_flags | O_NONBLOCK) == -1) {
        perror("Failed to set non-blocking mode");
        exit(EXIT_FAILURE);
    }

    while (attempts < retry + 1 && !confirmed) {
        if (sendto(sockfd, message, message_size, flags, address, address_size) == -1) {
            perror("Failed to send message");
            continue;
        }

        int poll_res = poll(fds, 1, timeout);
        if (poll_res == -1) {
            perror("Poll failed");
            break;
        } else if (poll_res == 0) {
            printf("Timeout occurred\n");
        } else {
            if (fds[0].revents & POLLIN) {
                char buffer[1024];
                ssize_t bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0, address, &address_size);
                if (bytes_received == -1) {
                    perror("Failed to receive message");
                    break;
                } else {
                    printf("Expected ID: %d\n", expectedMessageID);
                    // Received message ID and compare with expected ID
                    uint16_t receivedMessageID = (buffer[1] << 8) | buffer[2];
                    printf("Received ID: %d\n", receivedMessageID);
                    if (receivedMessageID == expectedMessageID) {
                        confirmed = 1;
                    }
                }
            }
        }

        attempts++;
    }

    // Восстанавливаем блокирующий режим сокета
    if (fcntl(sockfd, F_SETFL, current_flags) == -1) {
        perror("Failed to restore blocking mode");
        exit(EXIT_FAILURE);
    }

    return confirmed;
}

int Start_state(int sock, struct sockaddr_in* server_addr, socklen_t server_addr_len, int flags, uint8_t retry, uint16_t timeout) {
    bool valid = true;
    char username[MAX_USERNAME_LENGTH + 1];
    char secret[MAX_SECRET_LENGTH + 1];
    char line[BUFFER_SIZE];
    char message[BUFFER_SIZE];


    while (valid == true) {
        if (fgets(line, BUFFER_SIZE, stdin) == NULL) {
            printf("Error or end-of-file encountered\n");
            continue;
        }
        line[strcspn(line, "\n")] = 0; // Remove newline character
        if (strcmp(line, "/help") == 0) {
            handle_help();
            continue;
        }

        uint16_t networkOrderMessageID = htons(messageID); // Convert message ID to network byte order


        int argsFilled = sscanf(line, "/auth %s %s %s", username, secret, globalDisplayNameUDP); // Parse the input line
        printf("username: %s\n", username);
        printf("secret: %s\n", secret);
        printf("displayName: %s\n", globalDisplayNameUDP);
        size_t totalLength = 1 + // Тип сообщения
                             2 + // Message ID
                             strlen(username) + 1 +
                             strlen(globalDisplayNameUDP) + 1 +
                             strlen(secret) + 1;
        char* message = (char*)malloc(totalLength);
        if (!message) {
            perror("Failed to allocate memory for auth message");
            return ERROR_STATE;
        }

        size_t offset = 0;
        message[offset++] = '\x02'; // Тип сообщения AUTH

        // Добавляем Message ID
        message[offset++] = (char)((messageID >> 8) & 0xFF);
        message[offset++] = (char)(messageID & 0xFF);

        // Копируем username
        strcpy(message + offset, username);
        offset += strlen(username) + 1; // +1 для '\0'

        // Копируем displayName
        strcpy(message + offset, globalDisplayNameUDP);
        offset += strlen(globalDisplayNameUDP) + 1; // +1 для '\0'

        // Копируем secret
        strcpy(message + offset, secret);
        offset += strlen(secret) + 1; // +1 для '\0'

        print_hex(message, totalLength);
        printf("Message length: %d\n", totalLength);
        if (Check_username(username) != false && Check_secret(secret) != false &&
            Check_Displayname(globalDisplayNameUDP) != false && argsFilled == 3) {

            if (wait_confirm(sock, message, totalLength, (struct sockaddr*)server_addr, server_addr_len, flags, timeout, retry, messageID)) {
                printf("Authenticated with the server.\n");
                free (message);
                return AUTH_STATE; // auth state = 1
            } else {
                printf("Failed to authenticate with the server.\n");
                free (message);
                return ERROR_STATE; // error state = 3
            }


        }

    }
}

int Auth_state(int sock, struct sockaddr_in* server_addr, socklen_t server_addr_len, int flags, uint8_t retry, uint16_t timeout) {
    char buffer[BUFFER_SIZE];
    char username[MAX_USERNAME_LENGTH + 1];
    char secret[MAX_SECRET_LENGTH + 1];
    char line[BUFFER_SIZE];

    struct pollfd fds[2];
    int nfds = 2;

    fds[0].fd = sock;
    fds[0].events = POLLIN;
    fds[1].fd = STDIN_FILENO;
    fds[1].events = POLLIN;

    messageID += 0x0001;
    int wait_reply = 0;
    int connection = 1;



    while(connection == 1)
    {
        printf ("AUTH STATE INSIDE FUNCTION\n");
        pthread_mutex_lock(&terminateSignalMutex);
        if (errno == EINTR && terminateSignalReceived) {
            pthread_mutex_unlock(&terminateSignalMutex);
            return END_STATE;
        }
        pthread_mutex_unlock(&terminateSignalMutex);

        int ret = poll(fds, nfds, -1); // Ожидание бесконечно или до события
        if (ret < 0) {
            perror("poll");
            return ERROR_STATE;
        }

        if (fds[1].revents & POLLIN && wait_reply == 0) // Read from stdin
        {
            if (fgets(line, BUFFER_SIZE, stdin) == NULL) {
                if (feof(stdin)) {
                    printf("EOF detected. Exiting...\n");
                    return END_STATE;
                }
                printf("Error or end-of-file encountered\n");
                continue;
            }
            line[strcspn(line, "\n")] = 0; // Remove newline character
            if (strcmp(line, "/help") == 0) {
                handle_help();
                continue;
            }

            uint16_t networkOrderMessageID = htons(messageID); // Convert message ID to network byte order


            int argsFilled = sscanf(line, "/auth %s %s %s", username, secret, globalDisplayNameUDP); // Parse the input line
            printf("username: %s\n", username);
            printf("secret: %s\n", secret);
            printf("globalDisplayNameUDP: %s\n", globalDisplayNameUDP);
            size_t totalLength = 1 + // Тип сообщения
                                 2 + // Message ID
                                 strlen(username) + 1 +
                                 strlen(globalDisplayNameUDP) + 1 +
                                 strlen(secret) + 1;
            char* message = (char*)malloc(totalLength);
            if (!message) {
                perror("Failed to allocate memory for auth message");
                return ERROR_STATE;
            }

            size_t offset = 0;
            message[offset++] = '\x02'; // Тип сообщения AUTH

            // Добавляем Message ID
            message[offset++] = (char)((messageID >> 8) & 0xFF);
            message[offset++] = (char)(messageID & 0xFF);

            // Копируем username
            strcpy(message + offset, username);
            offset += strlen(username) + 1; // +1 для '\0'

            // Копируем displayName
            strcpy(message + offset, globalDisplayNameUDP);
            offset += strlen(globalDisplayNameUDP) + 1; // +1 для '\0'

            // Копируем secret
            strcpy(message + offset, secret);
            offset += strlen(secret) + 1; // +1 для '\0'

            print_hex(message, totalLength);
            printf("Message length: %d\n", totalLength);
            if (Check_username(username) != false && Check_secret(secret) != false &&
                Check_Displayname(globalDisplayNameUDP) != false && argsFilled == 3) {

                int send_auth = sendto(sock, message, totalLength, flags, (struct sockaddr*)server_addr, server_addr_len);
                if (send_auth == -1) {
                    perror("Failed to send message");
                    free (message);
                    return ERROR_STATE;
                }
                free(message);
                wait_reply = 1;
                messageID += 0x0001;
            } else {
                printf("Invalid input:\n");
            }


        }

        if (fds[0].revents & POLLIN) { // Read from the server
            int recv_reply = recvfrom(sock, buffer, BUFFER_SIZE, flags, (struct sockaddr*)server_addr, &server_addr_len);
            if (recv_reply == -1) {
                perror("Failed to receive message");
                return ERROR_STATE;
            }

            if(buffer[0] == 0x01){
                uint16_t receivedMessageID = (buffer[1] << 8) | buffer[2];
                printf("Received ID(CONFIRM_AUTH): %d\n", receivedMessageID);
                size_t totalLength = 1 + // Message type
                                     2;   // Message ID
                char* message = (char*)malloc(totalLength);
                size_t offset = 0;
                message[offset++] = '\x00'; // Confrim message type

                message[offset++] = (char)((messageID >> 8) & 0xFF);
                message[offset++] = (char)(messageID & 0xFF);

                print_hex(message, totalLength);
                printf("Message length: %d\n", totalLength);
                int send_confirm = sendto(sock, message, totalLength, flags, (struct sockaddr*)server_addr, server_addr_len);
                if (send_confirm == -1) {
                    perror("Failed to send message");
                    free(message);
                    return ERROR_STATE;
                }
                free(message);
                if(buffer[3] == 0x01) // If result is OK
                {
                    printf("Authenticated with the server aaa.\n");
                    return OPEN_STATE;
                }
                wait_reply = 0;

            }else if(buffer[0] == 0xFE){
                char *messageContent = "";
                uint16_t receivedMessageID = (buffer[1] << 8) | buffer[2];
                printf("Received ID(ERROR_AUTH): %d\n", receivedMessageID);
                size_t totalLength = 1 + // Message type
                                     2 +  // Message ID
                                     strlen(globalDisplayNameUDP) + 1 + // Длина displayName + '\0'
                                     strlen(messageContent) + 1;
                char* message = (char*)malloc(totalLength);

                size_t offset = 0;
                message[offset++] = '\xFE'; // Confrim message type
                message[offset++] = (char)((messageID >> 8) & 0xFF);
                message[offset++] = (char)(messageID & 0xFF);

                strcpy(message + offset, globalDisplayNameUDP);
                offset += strlen(globalDisplayNameUDP) + 1; // +1 для '\0'

                strcpy(message + offset, messageContent);
                offset += strlen(messageContent) + 1; // +1 для '\0'
                print_hex(message, totalLength);
                printf("Message length: %d\n", totalLength);
                int send_confirm_bye = sendto(sock, message, totalLength, flags, (struct sockaddr*)server_addr, server_addr_len);
                if (send_confirm_bye == -1) {
                    perror("Failed to send message");
                    free(message);
                    return ERROR_STATE;
                }
                free(message);

                int recieve_bye = recvfrom(sock, buffer, BUFFER_SIZE, flags, (struct sockaddr*)server_addr, &server_addr_len);
                if (recieve_bye == -1) {
                    perror("Failed to receive message");
                    return ERROR_STATE;
                }
                char *messageContent2 = "";
                receivedMessageID = (buffer[1] << 8) | buffer[2];
                printf("Received ID(BYE): %d\n", receivedMessageID);
                size_t totalLength2 = 1 + // Message type
                                      2 +  // Message ID
                                      strlen(globalDisplayNameUDP) + 1 + // Длина displayName + '\0'
                                      strlen(messageContent2) + 1;
                char* message2 = (char*)malloc(totalLength2);

                size_t offset2 = 0;
                message[offset2++] = '\xFE'; // Confrim message type
                message[offset2++] = (char)((messageID >> 8) & 0xFF);
                message[offset2++] = (char)(messageID & 0xFF);

                strcpy(message2 + offset2, globalDisplayNameUDP);
                offset2 += strlen(globalDisplayNameUDP) + 1; // +1 для '\0'

                strcpy(message2 + offset2, messageContent2);
                offset2 += strlen(messageContent2) + 1; // +1 для '\0'
                print_hex(message2, totalLength2);
                printf("Message length: %d\n", totalLength2);
                int send_confirm_bye2 = sendto(sock, message2, totalLength2, flags, (struct sockaddr*)server_addr, server_addr_len);
                if (send_confirm_bye2 == -1) {
                    perror("Failed to send message");
                    free(message2);
                    return ERROR_STATE;
                }
                free(message2);
                close(sock);
                exit(0);

            }
        }

    }
    // return OPEN_STATE;
}

int Open_state(int sock, struct sockaddr_in* server_addr, socklen_t server_addr_len, int flags, uint8_t retry, uint16_t timeout) {
    char buffer[BUFFER_SIZE];
    char buffer2[BUFFER_SIZE];
    char line[BUFFER_SIZE];
    char channelID[MAX_CHANNEL_ID_LENGTH + 1];

    struct pollfd fds[2];


    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;
    fds[1].fd = sock;
    fds[1].events = POLLIN;

    int recieving = 0;
    int wait_for_confirm = 0;
    int Retries = 0;
    int reply_recieved = 0;
    size_t totalLength2;
    int timeoutml = timeout;

    while(recieving == 0){

        printf("Reply(OPEN) is %d\n", reply_recieved);
        pthread_mutex_lock(&terminateSignalMutex);
        if (errno == EINTR && terminateSignalReceived) {
            pthread_mutex_unlock(&terminateSignalMutex);
            return END_STATE;
        }
        pthread_mutex_unlock(&terminateSignalMutex);

        int ret = poll(fds, 2, POLL_TIMEOUT); // wait for event
        if (ret < 0) {
            perror("poll");
            return ERROR_STATE;
        }



        if (fds[0].revents & POLLIN) {
            if (fgets(line, BUFFER_SIZE, stdin) == NULL) {
                if (feof(stdin)) {
                    printf("EOF detected. Exiting...\n");
                    return END_STATE;
                }
                printf("Error or end-of-file encountered\n");
                continue;
            }
            line[strcspn(line, "\n")] = 0; // Remove newline character

            if(strlen(line) == 0){
                printf("Line is empty\n");

            }else{
                if (reply_recieved == 0) {
                    if (strncmp(line, "/join ", 6) == 0) {
                        uint16_t networkOrderMessageID = htons(messageID);
                        int argsFilled = sscanf(line, "/join %s", channelID);
                        printf("Channel ID: %s\n", channelID);
                        size_t totalLength = 1 + // Тип сообщения
                                             2 + // Message ID
                                             strlen(channelID) + 1 +
                                             strlen(globalDisplayNameUDP) + 1;

                        char* message = (char*)malloc(totalLength);
                        if (!message) {
                            perror("Failed to allocate memory for auth message");
                            return ERROR_STATE;
                        }

                        size_t offset = 0;
                        message[offset++] = '\x03'; // Тип сообщения AUTH

                        // Добавляем Message ID
                        message[offset++] = (char)((messageID >> 8) & 0xFF);
                        message[offset++] = (char)(messageID & 0xFF);

                        // copy channelID
                        strcpy(message + offset, channelID);
                        offset += strlen(channelID) + 1; // +1 для '\0'

                        // Копируем displayName
                        strcpy(message + offset, globalDisplayNameUDP);
                        offset += strlen(globalDisplayNameUDP) + 1; // +1 для '\0'
                        print_hex(message, totalLength);
                        printf("Message length(JOIN): %d\n", totalLength);

                        memcpy(buffer2, message, totalLength);
                        totalLength2 = totalLength;

                        int send_join = sendto(sock, message, totalLength, flags, (struct sockaddr*)server_addr, server_addr_len);
                        if (send_join == -1) {
                            perror("Failed to send message");
                            free (message);
                            return ERROR_STATE;
                        }
                        free (message);
                        reply_recieved = 0;
                        messageID += 0x0001;
                        wait_for_confirm = 1;
                    } else if (strncmp(line, "/rename ", 8) == 0) {
                        char newDisplayName[MAX_DISPLAY_NAME_LENGTH + 1];
                        sscanf(line, "/rename %20s", newDisplayName);


                        if(!Check_Displayname(newDisplayName)) {
                            printf("Error: Validation failed for display name.\n");

                        }else {
                            // Copy the new display name to the global variable
                            strncpy(globalDisplayNameUDP, newDisplayName, MAX_DISPLAY_NAME_LENGTH);
                            globalDisplayNameUDP[MAX_DISPLAY_NAME_LENGTH] = '\0'; // Add null terminator
                            printf("Your new Name: %s\n", newDisplayName);
                        }


                    }
                    else if(strncmp(line, "/help ", 8) == 0){
                        handle_help();

                    }
                    else { // sending message
                        uint16_t networkOrderMessageID = htons(messageID);
                        size_t totalLength = 1 + // Тип сообщения
                                             2 + // Message ID
                                             strlen(channelID) + 1 +
                                             strlen(globalDisplayNameUDP) + 1
                                             + strlen(line) + 1;

                        char* message = (char*)malloc(totalLength);
                        if (!message) {
                            perror("Failed to allocate memory for auth message");
                            return ERROR_STATE;
                        }

                        size_t offset = 0;
                        message[offset++] = '\x04'; // Тип сообщения AUTH

                        // Добавляем Message ID
                        message[offset++] = (char)((messageID >> 8) & 0xFF);
                        message[offset++] = (char)(messageID & 0xFF);

                        // Копируем displayName
                        strcpy(message + offset, globalDisplayNameUDP);
                        offset += strlen(globalDisplayNameUDP) + 1; // +1 для '\0

                        // add message content
                        strcpy(message + offset, line);
                        offset += strlen(line) + 1; // +1 для '\0'
                        // '
                        print_hex(message, totalLength);
                        printf("Message length(MSG): %d\n", totalLength);

                        int send_msg = sendto(sock, message, totalLength, flags, (struct sockaddr*)server_addr, server_addr_len);
                        if (send_msg == -1) {
                            perror("Failed to send message");
                            free (message);
                            return ERROR_STATE;
                        }
                        free (message);
                        wait_for_confirm = true;
                        messageID += 0x0001;



                    }
                }

            }


        }

        if (fds[1].revents & POLLIN) { // Read from the server
            int recv_reply = recvfrom(sock, buffer, BUFFER_SIZE, flags, (struct sockaddr *) server_addr,
                                      &server_addr_len);
            if (recv_reply == -1) {
                perror("Failed to receive message");
                return ERROR_STATE;
            }

            if(buffer[0] == 0x01) // reply
            {
                uint16_t receivedMessageID = (buffer[1] << 8) | buffer[2];
                printf("Received ID(OPEN_REPLY): %d\n", receivedMessageID);
                size_t totalLength = 1 + // Message type
                                     2;   // Message ID
                char* message = (char*)malloc(totalLength);
                size_t offset = 0;
                message[offset++] = '\x00'; // Confrim message type

                message[offset++] = (char)((messageID >> 8) & 0xFF);
                message[offset++] = (char)(messageID & 0xFF);

                print_hex(message, totalLength);
                printf("Message length(REPLY FROM SERVER): %d\n", totalLength);
                int send_confirm = sendto(sock, message, totalLength, flags, (struct sockaddr*)server_addr, server_addr_len);
                if (send_confirm == -1) {
                    perror("Failed to send message");
                    free(message);
                    return ERROR_STATE;
                }
                free(message);
                reply_recieved = 0;
                recieving = 0;

            }
            else if(buffer[0] == 0x04) // message
            {
                uint16_t receivedMessageID = (buffer[1] << 8) | buffer[2];
                printf("Received ID(OPEN_REPLY): %d\n", receivedMessageID);
                size_t totalLength = 1 + // Message type
                                     2;   // Message ID
                char* message = (char*)malloc(totalLength);
                size_t offset = 0;
                message[offset++] = '\x00'; // Confrim message type

                message[offset++] = (char)((messageID >> 8) & 0xFF);
                message[offset++] = (char)(messageID & 0xFF);

                print_hex(message, totalLength);
                printf("Message length(MSG FROM SERVER): %d\n", totalLength);
                int send_confirm = sendto(sock, message, totalLength, flags, (struct sockaddr*)server_addr, server_addr_len);
                if (send_confirm == -1) {
                    perror("Failed to send message");
                    free(message);
                    return ERROR_STATE;
                }
                free(message);
                recieving = 0;


            }else if(buffer[0] == 0xFE) // error
            {
                uint16_t receivedMessageID = (buffer[1] << 8) | buffer[2];
                printf("Received ID(OPEN_REPLY): %d\n", receivedMessageID);
                size_t totalLength = 1 + // Message type
                                     2;   // Message ID
                char* message = (char*)malloc(totalLength);
                size_t offset = 0;
                message[offset++] = '\x00'; // Confrim message type

                message[offset++] = (char)((messageID >> 8) & 0xFF);
                message[offset++] = (char)(messageID & 0xFF);

                print_hex(message, totalLength);
                printf("Message length(ERROR OPEN): %d\n", totalLength);
                int send_confirm_error = sendto(sock, message, totalLength, flags, (struct sockaddr*)server_addr, server_addr_len);
                if (send_confirm_error == -1) {
                    perror("Failed to send message");
                    free(message);
                    return ERROR_STATE;
                }
                free(message);
            }
            else if(buffer[0] == 0xFF)
            {
                uint16_t receivedMessageID = (buffer[1] << 8) | buffer[2];
                printf("Received ID(OPEN_REPLY): %d\n", receivedMessageID);
                size_t totalLength = 1 + // Message type
                                     2;   // Message ID
                char* message = (char*)malloc(totalLength);
                size_t offset = 0;
                message[offset++] = '\x00'; // Confrim message type

                message[offset++] = (char)((messageID >> 8) & 0xFF);
                message[offset++] = (char)(messageID & 0xFF);

                print_hex(message, totalLength);
                printf("Message length(MSG FROM SERVER): %d\n", totalLength);
                int send_confirm_bye = sendto(sock, message, totalLength, flags, (struct sockaddr*)server_addr, server_addr_len);
                if (send_confirm_bye == -1) {
                    perror("Failed to send message");
                    free(message);
                    return ERROR_STATE;
                }
                free(message);
                recieving = 0;
                close(sock);
                exit(0);
            }
            else if(buffer[0] == 0x00)
            {
                wait_for_confirm = 0;
            }
            else{
                printf("Unknown message type\n");
            }
        }

    }
      //return END_STATE;
}

int End_state(int sock, struct sockaddr_in* server_addr, socklen_t server_addr_len, int flags, uint8_t retry, uint16_t timeout){
    uint16_t networkOrderMessageID = htons(messageID);
    size_t totalLength = 1 + // Тип сообщения
                         2; // Message ID


    char* message = (char*)malloc(totalLength);
    if (!message) {
        perror("Failed to allocate memory for auth message");
        return ERROR_STATE;
    }

    size_t offset = 0;
    message[offset++] = '\xFF'; // Тип сообщения AUTH

    // Добавляем Message ID
    message[offset++] = (char)((messageID >> 8) & 0xFF);
    message[offset++] = (char)(messageID & 0xFF);

    // '
    print_hex(message, totalLength);
    printf("Message length(BYE MESSAGE): %d\n", totalLength);

    wait_confirm(sock, message, totalLength, (struct sockaddr*)server_addr, server_addr_len, flags, timeout, retry, messageID);
    free (message);
    close(sock);
    exit(0);
}

int Error_state(int sock, struct sockaddr_in* server_addr, socklen_t server_addr_len, int flags, uint8_t retry, uint16_t timeout){
    char line[BUFFER_SIZE] = "Error";

    uint16_t networkOrderMessageID = htons(messageID);
    size_t totalLength = 1 + // Тип сообщения
                         2+ // Message ID
                         strlen(globalDisplayNameUDP) + 1
                         + strlen(line) + 1;


    char* message = (char*)malloc(totalLength);
    if (!message) {
        perror("Failed to allocate memory for auth message");
        return ERROR_STATE;
    }

    size_t offset = 0;
    message[offset++] = '\xFE';

    // Добавляем Message ID
    message[offset++] = (char)((messageID >> 8) & 0xFF);
    message[offset++] = (char)(messageID & 0xFF);
    strcpy(message + offset, globalDisplayNameUDP);
    offset += strlen(globalDisplayNameUDP) + 1; // +1 для '\0
    strcpy(message + offset, line);
    offset += strlen(line) + 1; // +1 для '\0'

    print_hex(message, totalLength);
    printf("Message length(ERROR MESSAGE): %d\n", totalLength);

    wait_confirm(sock, message, totalLength, (struct sockaddr*)server_addr, server_addr_len, flags, timeout, retry, messageID);
    free (message);
    messageID += 0x0001;
    return END_STATE;
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


    State state = START_STATE;
    int flags = 0;
    uint16_t timeout = 25000;
    uint8_t retry = 3;

    while(1) {
        switch (state) {
            case START_STATE: {
                state = Start_state(sock, &server_addr, sizeof(server_addr), flags, retry, timeout );
                printf("START state\n");
                break;
            }

            case AUTH_STATE: {
                printf("AUTH state\n");
                state = Auth_state(sock, &server_addr, sizeof(server_addr), flags, retry, timeout);
                break;
            }

            case OPEN_STATE: {
                printf("OPEN state\n");

                state = Open_state(sock, &server_addr, sizeof(server_addr), flags, retry, timeout);
                break;
            }

            case ERROR_STATE: {
                printf("ERROR state\n");
                state = Error_state(sock, &server_addr, sizeof(server_addr), flags, retry, timeout);
                break;
            }

            case END_STATE: {
                printf("END state\n");
                state = End_state(sock, &server_addr, sizeof(server_addr), flags, retry, timeout);
                break;
            }


        }

    }


}
int main(int argc, char *argv[]){
    //
    parse_arguments(argc, argv);
    //
    signal(SIGINT, signalHandler);

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





