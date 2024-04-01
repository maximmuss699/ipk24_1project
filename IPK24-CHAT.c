/**
 * @file IPK24-CHAT.c
 *
 * @name IPK project 1 - Chat client
 * @brief Chat application client
 * @author Maksim Samusevich(xsamus00)
 * @date 01.04.2024
 */

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
#include <errno.h>
#include <signal.h>
#include <netdb.h>
#include <pthread.h>


#define BUFFER_SIZE 1024
#define DEFAULT_SERVER_PORT 4567
#define POLL_TIMEOUT 20000
#define MAX_USERNAME_LENGTH 20
#define MAX_SECRET_LENGTH 128
#define MAX_DISPLAY_NAME_LENGTH 20
#define MAX_CHANNEL_ID_LENGTH 20

// variables for handling the termination signal
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

char Display_name[MAX_DISPLAY_NAME_LENGTH + 1] = ""; // Display name for the client


typedef enum {
    START_STATE,
    AUTH_STATE,
    OPEN_STATE,
    ERROR_STATE,
    END_STATE
} State;

// global message ID
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
        fprintf(stderr, "ERR: bad protocol\n");
        exit(EXIT_FAILURE);
    }
}





// Function to handle the server response in TCP protocol
int handle_response(char *response, int sock, State state) {
    // Check if the response is a REPLY type with success or failure message
    char type[6]; // Buffer to store the message type
    char status[4]; // Buffer to store the status (OK/NOK)
    char content[BUFFER_SIZE]; // Buffer to store the message content
    char displayName[BUFFER_SIZE] = {0};

    if (state == AUTH_STATE) {

        if (sscanf(response, "%5s %3s IS %[^\r\n]", type, status, content) == 3) {
            if ((strcmp(type, "REPLY") == 0) || (strcmp(type, "reply") == 0)) {
                if ((strcmp(status, "OK") == 0) || (strcmp(status, "ok") == 0)) {
                    printf("Success: %s\n", content);
                    return 0;
                } else if ((strcmp(status, "NOK") == 0) || (strcmp(status, "nok") == 0)) {
                    printf("Failure: %s\n", content);
                    return 1;

                } else {

                    return 3;
                }
            } else {

                return 3;

            }
        } else if ((strncmp(response, "ERR", 3) == 0) || (strncmp(response, "err", 3) == 0)) {
            // ERR
            if (sscanf(response, "ERR FROM %[^ ] IS %[^\r\n]", displayName, content) == 2 ||
                sscanf(response, "err from %[^ ] is %[^\r\n]", displayName, content) == 2) {
                fprintf(stderr, "ERR FROM %s: %s\n", displayName, content);
                return 2;
            } else {

                return 3;
            }
        }
    } else if (state == OPEN_STATE) {

            if (sscanf(response, "%5s %3s IS %[^\r\n]", type, status, content) == 3) {
                if ((strcmp(type, "REPLY") == 0) || (strcmp(type, "reply") == 0)) {
                    if ((strcmp(status, "OK") == 0) || (strcmp(status, "ok") == 0)) {
                        printf("Success: %s\n", content);
                        return 0;
                    } else if ((strcmp(status, "NOK") == 0) || (strcmp(status, "nok") == 0)) {
                        printf("Failure: %s\n", content);
                        return 1;

                    } else {

                        return 3;
                    }
                } else {

                    return 3;

                }
            } else if ((strncmp(response, "ERR", 3) == 0) || (strncmp(response, "err", 3) == 0)) {
                // ERR
                if (sscanf(response, "ERR FROM %[^ ] IS %[^\r\n]", displayName, content) == 2 ||
                    sscanf(response, "err from %[^ ] is %[^\r\n]", displayName, content) == 2) {
                    fprintf(stderr, "ERR FROM %s: %s\n", displayName, content);
                    return 2;
                } else {

                    return 3;
                }

            } else if (strncmp(response, "BYE", 3) == 0 || strncmp(response, "bye", 3) == 0) {
                close(sock);
                exit(0);

            } else if (strncmp(response, "MSG FROM", 8) == 0 || strncmp(response, "msg from", 8) == 0) {
                char Server_name[MAX_DISPLAY_NAME_LENGTH + 1];
                if (sscanf(response, "MSG FROM %20s IS %[^\r\n]", Server_name, content) == 2 ||
                    sscanf(response, "msg from %20s is %[^\r\n]", Server_name, content) == 2) {
                    printf("%s: %s\n", Server_name, content);
                }

            } else {

                return 3;
            }


        }
    }



int Start_stateTCP(int sock ){
    char message[BUFFER_SIZE] = {0};
    char auth_message[BUFFER_SIZE];
    char username[MAX_USERNAME_LENGTH + 1];
    char secret[MAX_SECRET_LENGTH + 1];
    char displayName[MAX_DISPLAY_NAME_LENGTH + 1];
    int send_auth = 0;
    while (send_auth == 0) {

        if (fgets(message, BUFFER_SIZE, stdin) == NULL) {
            fprintf(stderr, "ERR: end-of-file encountered\n");
            break;
        }
        message[strcspn(message, "\n")] = 0; // Remove newline character
        if (message[0] == '\0') {
            fprintf(stderr, "ERR: Line is empty.\n");
        }else if(strncmp(message, "/help ", 6) == 0){
            handle_help();
        }
        else{
            if (strncmp(message, "/auth ", 6) == 0) {
                int argsFilled = sscanf(message, "/auth %s %s %s", username, secret, displayName);
                if (Check_username(username) == true && Check_secret(secret) == true && Check_Displayname(displayName) == true && argsFilled == 3) {
                    strncpy(Display_name, displayName, MAX_DISPLAY_NAME_LENGTH);
                    Display_name[MAX_DISPLAY_NAME_LENGTH] = '\0';
                    snprintf(auth_message, BUFFER_SIZE, "AUTH %s AS %s USING %s\r\n", username, displayName, secret);


                    if (send(sock, auth_message, strlen(auth_message), 0) < 0) {
                        perror("Error sending AUTH message");
                    }
                    send_auth = 1;
                    return AUTH_STATE;

                }else{
                    fprintf(stderr, "ERR: Incorrect AUTH command format.\n");
                }
            } else {
                fprintf(stderr, "ERR: Incorrect AUTH command format.\n");
            }

        }

    }
    return AUTH_STATE;
}

int AUTH_STATETCP(int sock, State state) {
    char message[BUFFER_SIZE] = {0};
    char auth_message[BUFFER_SIZE];
    char username[MAX_USERNAME_LENGTH + 1];
    char secret[MAX_SECRET_LENGTH + 1];
    char displayName[MAX_DISPLAY_NAME_LENGTH + 1];
    char newDisplayName[MAX_DISPLAY_NAME_LENGTH + 1];
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
                    fprintf(stderr, "ERR: Server error.\n");
                    exit(1);
                }
                buffer[bytes_received] = '\0';

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
                    fprintf(stderr, "ERR: stdin \n");
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
                        strncpy(Display_name, displayName, MAX_DISPLAY_NAME_LENGTH);
                        Display_name[MAX_DISPLAY_NAME_LENGTH] = '\0';
                        snprintf(auth_message, BUFFER_SIZE, "AUTH %s AS %s USING %s\r\n", username, displayName,
                                 secret);


                        if (send(sock, auth_message, strlen(auth_message), 0) < 0) {
                            perror("Error sending AUTH message");
                        }
                        recv_reply = 1;

                    } else {
                        fprintf(stderr, "ERR: Incorrect AUTH command format.\n");
                    }
                } else if (strncmp(message, "/rename ", 8) == 0) {
                    int argsFilled = sscanf(message, "/rename %20s", newDisplayName);
                    if (argsFilled == 1 && Check_Displayname(newDisplayName)) {

                        // Copy the new display name to the global variable
                        strncpy(Display_name, newDisplayName, MAX_DISPLAY_NAME_LENGTH);
                        Display_name[MAX_DISPLAY_NAME_LENGTH] = '\0';


                    } else {
                        fprintf(stderr, "ERR: Incorrect RENAME command format.\n");
                    }
                }
                else {
                    if (strncmp(message, "/help ", 6) == 0) {
                        handle_help();
                    }else {
                        fprintf(stderr, "ERR: Incorrect command\n");
                    }
                }


            }
        }
    }
}


int Open_stateTCP(int sock, State state) {
    char message[BUFFER_SIZE] = {0};
    char channelID[MAX_CHANNEL_ID_LENGTH + 1];
    char newDisplayName[MAX_DISPLAY_NAME_LENGTH + 1];
    struct pollfd fds[2];
    fds[0].fd = sock;
    fds[0].events = POLLIN;
    fds[1].fd = STDIN_FILENO;
    fds[1].events = POLLIN;
    int open_state = 1;
    int recv_reply = 0;
    while (open_state == 1) {


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
                    fprintf(stderr, "ERR: Server error.\n");
                    exit(1);
                }
                buffer[bytes_received] = '\0';

                int response = handle_response(buffer, sock, state);

                if (response == 0){
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
            if (fds[1].revents & POLLIN ) // Stdin
            {
                if (fgets(message, BUFFER_SIZE, stdin) == NULL) {
                    fprintf(stderr, "ERR: EOF.\n");
                    break;
                }
                if (feof(stdin)) {
                    open_state = 1;
                    return END_STATE;
                }
                message[strcspn(message, "\n")] = 0; // Remove newline character

                if(recv_reply == 0) {
                    if (strncmp(message, "/join ", 6) == 0) {
                        int argsFilled = sscanf(message, "/join %20s", channelID);
                        if (argsFilled == 1 && strlen(channelID) <= MAX_CHANNEL_ID_LENGTH) {

                            char join_message[BUFFER_SIZE];
                            snprintf(join_message, BUFFER_SIZE, "JOIN %s AS %s\r\n", channelID, Display_name);
                            if (send(sock, join_message, strlen(join_message), 0) < 0) {
                                perror("Error sending JOIN message");
                                open_state = 0;
                                return ERROR_STATE;
                            }

                            recv_reply = 1;
                        } else {
                            fprintf(stderr, "ERR: Incorrect JOIN command format.\n");
                        }
                    } else if (strncmp(message, "/rename ", 8) == 0) {
                        int argsFilled = sscanf(message, "/rename %20s", newDisplayName);
                        if (argsFilled == 1 && Check_Displayname(newDisplayName)) {

                            // Copy the new display name to the global variable
                            strncpy(Display_name, newDisplayName, MAX_DISPLAY_NAME_LENGTH);
                            Display_name[MAX_DISPLAY_NAME_LENGTH] = '\0';


                        } else {
                            fprintf(stderr, "ERR: Incorrect RENAME command format.\n");
                        }
                    } else if (strncmp(message, "/help", 5) == 0) {
                        handle_help();
                    } else {
                        char msg_message[BUFFER_SIZE];
                        snprintf(msg_message, BUFFER_SIZE, "MSG FROM %s IS %s\r\n", Display_name, message);
                        if (send(sock, msg_message, strlen(msg_message), 0) < 0) {
                            perror("Error sending MSG message");
                            open_state = 0;
                            return ERROR_STATE;
                        }
                        printf("%s: %s\n", Display_name, message);

                    }

                }
            }
        }
    }
}

int Error_stateTCP(int sock) {
    const char* ERRessage = "error\r\n";
    char msg_message[BUFFER_SIZE];
    snprintf(msg_message, BUFFER_SIZE, "ERR FROM %s IS %s\r\n", Display_name, ERRessage);
    if (send(sock, msg_message, strlen(msg_message), 0) < 0) {
        perror("Error sending BYE message");
        return ERROR_STATE;
    }
    return END_STATE;
}

int End_stateTCP(int sock) {
    const char* byeMessage = "BYE\r\n";
    if (send(sock, byeMessage, strlen(byeMessage), 0) < 0) {
        perror("Error sending ERR");
        return ERROR_STATE;
    }
    close(sock);
    exit(EXIT_FAILURE);

}


void tcp_client() {
    int sock;
    struct sockaddr_in server_addr;
    struct hostent* he;
    struct pollfd fds[2];


    if ((he = gethostbyname(config.server_ip)) == NULL) {
        herror("gethostbyname");
        exit(EXIT_FAILURE);
    }


    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }


    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config.server_port);
    server_addr.sin_addr = *((struct in_addr*)he->h_addr);


    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        exit(EXIT_FAILURE);
    }


    State state = START_STATE;

    while (1) {

        switch (state) {
            case START_STATE:

                state = Start_stateTCP(sock);
                break;
            case AUTH_STATE:

                state = AUTH_STATETCP(sock, state);
                break;
            case OPEN_STATE:

                state = Open_stateTCP(sock, state);
                break;
            case ERROR_STATE:

                state = Error_stateTCP(sock);
                break;
            case END_STATE:

                state = End_stateTCP(sock);
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


int wait_confirm(int sock, const char* message, size_t message_size, struct sockaddr* address, socklen_t address_size, uint16_t timeout, uint8_t retry, uint16_t expectedMessageID) {
    struct pollfd fds[1];
    char buffer[BUFFER_SIZE];
    fds[0].fd = sock;
    fds[0].events = POLLIN;
    int try = 0;
    int confirm = 0;
    // IF the message is not confirmed, retry sending the message
    // until the maximum number of retries is reached
    // 1 initial try + retries
    while (try < retry + 1 && !confirm) {
        if (sendto(sock, message, message_size, 0, address, address_size) == -1) {
            perror("Failed to send message");
            continue;
        }

        int poll_res = poll(fds, 1, timeout);
        if (poll_res == -1) {
            perror("Poll failed");
            break;
        } else if (poll_res == 0) {
            fprintf(stderr, "ERR: timout.\n");
        } else {
            if (fds[0].revents & POLLIN) {
                ssize_t bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, address, &address_size);
                if (bytes_received == -1) {
                    perror("Failed to receive message");
                    break;
                } else {
                    // Received message ID and compare with expected ID
                    uint16_t receivedMessageID = (buffer[1] << 8) | buffer[2];
                    if (receivedMessageID == expectedMessageID) {
                        confirm = 1;
                    }
                }
            }
        }

        try++;
    }
    return confirm;
}

int Start_state(int sock, struct sockaddr_in* server_addr, socklen_t server_addr_len, uint8_t retry, uint16_t timeout) {
    bool valid = true;
    char username[MAX_USERNAME_LENGTH + 1];
    char secret[MAX_SECRET_LENGTH + 1];
    char line[BUFFER_SIZE];



    while (valid == true) {
        if (fgets(line, BUFFER_SIZE, stdin) == NULL) {
            fprintf(stderr, "ERR: EOF.\n");
            continue;
        }
        line[strcspn(line, "\n")] = 0; // Remove newline character
        if (strcmp(line, "/help") == 0) {
            handle_help();
            continue;
        }



        int argsFilled = sscanf(line, "/auth %s %s %s", username, secret, Display_name); // Parse the input line
        size_t totalLength = 1 + // Message type
                             2 + // Message ID
                             strlen(username) + 1 +
                             strlen(Display_name) + 1 +
                             strlen(secret) + 1;
        char* message = (char*)malloc(totalLength);
        if (!message) {
            perror("Failed to allocate memory for auth message");
            return ERROR_STATE;
        }

        uint16_t netOrderMessageID = htons(messageID); // Convert message ID to network byte order
        size_t offset = 0;
        message[offset++] = '\x02';


        message[offset++] = (char)((netOrderMessageID >> 8) & 0xFF);
        message[offset++] = (char)(netOrderMessageID & 0xFF);


        strcpy(message + offset, username);
        offset += strlen(username) + 1;


        strcpy(message + offset, Display_name);
        offset += strlen(Display_name) + 1;


        strcpy(message + offset, secret);
        offset += strlen(secret) + 1;


        if (Check_username(username) != false && Check_secret(secret) != false &&
            Check_Displayname(Display_name) != false && argsFilled == 3) {

            if (wait_confirm(sock, message, totalLength, (struct sockaddr*)server_addr, server_addr_len, timeout, retry, netOrderMessageID)) {
                free (message);
                return AUTH_STATE; // auth state = 1
            } else {

                free (message);
                return ERROR_STATE; // error state = 3
            }


        }

    }
}

int Auth_state(int sock, struct sockaddr_in* server_addr, socklen_t server_addr_len, uint8_t retry, uint16_t timeout) {
    char buffer[BUFFER_SIZE];
    char username[MAX_USERNAME_LENGTH + 1];
    char secret[MAX_SECRET_LENGTH + 1];
    char line[BUFFER_SIZE];
    char newDisplayName[MAX_DISPLAY_NAME_LENGTH + 1];

    struct pollfd fds[2];
    fds[0].fd = sock;
    fds[0].events = POLLIN;
    fds[1].fd = STDIN_FILENO;
    fds[1].events = POLLIN;

    messageID += 0x0001;
    int wait_reply = 0;
    int connection = 1;



    while(connection == 1)
    {

        pthread_mutex_lock(&terminateSignalMutex);
        if (errno == EINTR && terminateSignalReceived) {
            pthread_mutex_unlock(&terminateSignalMutex);
            return END_STATE;
        }
        pthread_mutex_unlock(&terminateSignalMutex);

        int ret = poll(fds, 2, -1);
        if (ret < 0) {
            perror("poll");
            return ERROR_STATE;
        }

        if (fds[1].revents & POLLIN && wait_reply == 0) // Read from stdin
        {
            if (fgets(line, BUFFER_SIZE, stdin) == NULL) {
                if (feof(stdin)) {
                    fprintf(stderr, "ERR: EOF.\n");
                    return END_STATE;
                }
                fprintf(stderr, "ERR: EOF.\n");
                continue;
            }

            line[strcspn(line, "\n")] = 0; // Remove newline character
            if (strcmp(line, "/help") == 0) {
                handle_help();
                continue;
            } else if (strncmp(line, "/rename ", 8) == 0) {
                int argsFilled = sscanf(line, "/rename %20s", newDisplayName);
                if (argsFilled == 1 && Check_Displayname(newDisplayName)) {

                    // Copy the new display name to the global variable
                    strncpy(Display_name, newDisplayName, MAX_DISPLAY_NAME_LENGTH);
                    Display_name[MAX_DISPLAY_NAME_LENGTH] = '\0';


                } else {
                    fprintf(stderr, "ERR: Incorrect RENAME.\n");
                }
            }

            uint16_t netOrderMessageID = htons(messageID); // Convert message ID to network byte order
            int argsFilled = sscanf(line, "/auth %s %s %s", username, secret, Display_name); // Parse the input line
            size_t totalLength = 1 + // Message type
                                 2 + // Message ID
                                 strlen(username) + 1 +
                                 strlen(Display_name) + 1 +
                                 strlen(secret) + 1;
            char* message = (char*)malloc(totalLength);
            if (!message) {
                perror("Failed to allocate memory for auth message");
                return ERROR_STATE;
            }

            size_t offset = 0;
            message[offset++] = '\x02'; // Message type AUTH

            message[offset++] = (char)((netOrderMessageID >> 8) & 0xFF);
            message[offset++] = (char)(netOrderMessageID & 0xFF);


            strcpy(message + offset, username);
            offset += strlen(username) + 1;


            strcpy(message + offset, Display_name);
            offset += strlen(Display_name) + 1;


            strcpy(message + offset, secret);
            offset += strlen(secret) + 1;


            if (Check_username(username) != false && Check_secret(secret) != false &&
                Check_Displayname(Display_name) != false && argsFilled == 3) {

                int send_auth = sendto(sock, message, totalLength,0 , (struct sockaddr*)server_addr, server_addr_len);
                if (send_auth == -1) {
                    perror("Failed to send message");
                    free (message);
                    return ERROR_STATE;
                }
                free(message);
                wait_reply = 1;
                messageID += 0x0001;
            } else {
                fprintf(stderr, "ERR: invalid input.\n");
            }


        }

        if (fds[0].revents & POLLIN) { // Read from the server
            int recv_reply = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr*)server_addr, &server_addr_len);
            if (recv_reply == -1) {
                perror("Failed to receive message");
                return ERROR_STATE;
            }

            if(buffer[0] == 0x01){
                uint16_t receivedMessageID = (buffer[1] << 8) | buffer[2];
                size_t totalLength = 1 + // Message type
                                     2;   // Message ID
                char* message = (char*)malloc(totalLength);
                size_t offset = 0;
                message[offset++] = '\x00'; // Confrim message type

                message[offset++] = (char)((receivedMessageID >> 8) & 0xFF);
                message[offset++] = (char)(receivedMessageID & 0xFF);
                char* content_buffer = (char*)malloc(BUFFER_SIZE);
                if(!content_buffer){
                    perror("Failed to allocate memory for content buffer");
                    return ERROR_STATE;
                }
                if(buffer[3] == 0x01) // If result is OK
                {
                    int j = 0;
                    for (int i = 6; buffer[i] != '\0'; i++, j++) {
                        content_buffer[j] += buffer[i];
                    }
                    printf("Success: %s\n", content_buffer);


                }else{
                    int j = 0;
                    for (int i = 6; buffer[i] != '\0'; i++, j++) {
                        content_buffer[j] += buffer[i];
                    }
                    printf("Failure: %s\n", content_buffer);

                }
                free(content_buffer);

                int send_confirm = sendto(sock, message, totalLength, 0, (struct sockaddr*)server_addr, server_addr_len);
                if (send_confirm == -1) {
                    perror("Failed to send message");
                    free(message);
                    return ERROR_STATE;
                }
                free(message);
                if(buffer[3] == 0x01) // If result is OK
                {

                    return OPEN_STATE;
                }
                wait_reply = 0;

            }else if(buffer[0] == 0xFE)
            {

                uint16_t receivedMessageID = (buffer[1] << 8) | buffer[2];
                size_t totalLength = 1 + // Message type
                                     2;   // Message ID
                char* message = (char*)malloc(totalLength);
                size_t offset = 0;
                message[offset++] = '\x00'; // Confrim message type

                message[offset++] = (char)((receivedMessageID >> 8) & 0xFF);
                message[offset++] = (char)(receivedMessageID & 0xFF);

                int send_confirm_err = sendto(sock, message, totalLength, 0, (struct sockaddr*)server_addr, server_addr_len);
                if (send_confirm_err == -1) {
                    perror("Failed to send message");
                    free(message);
                    return ERROR_STATE;
                }
                free(message);

                int recieve_bye = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr*)server_addr, &server_addr_len);
                if (recieve_bye == -1) {
                    perror("Failed to receive message");
                    return ERROR_STATE;
                }
                receivedMessageID = (buffer[1] << 8) | buffer[2];
                size_t totalLength2 = 1 + // Message type
                                     2;   // Message ID
                char* message2 = (char*)malloc(totalLength);
                size_t offset2 = 0;
                message[offset++] = '\x00'; // Confrim message type

                message2[offset2++] = (char)((receivedMessageID >> 8) & 0xFF);
                message2[offset2++] = (char)(receivedMessageID & 0xFF);

                int send_confirm_bye2 = sendto(sock, message2, totalLength2, 0, (struct sockaddr*)server_addr, server_addr_len);
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

}

int Open_state(int sock, struct sockaddr_in* server_addr, socklen_t server_addr_len, uint8_t retry, uint16_t timeout) {
    char buffer[BUFFER_SIZE];
    char buffer2[BUFFER_SIZE]; // Buffer for resending messages
    char line[BUFFER_SIZE];
    char channelID[MAX_CHANNEL_ID_LENGTH + 1];
    char newDisplayName[MAX_DISPLAY_NAME_LENGTH + 1];

    struct pollfd fds[2];

    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;
    fds[1].fd = sock;
    fds[1].events = POLLIN;

    int recieving = 0;
    int waiting_confirm = 0;
    int Retries = 0;
    int reply_recieved = 0;
    size_t totalLength2;
    uint16_t netOrderMessageID2;


    while(recieving == 0){

        int pollTimeout = waiting_confirm ? timeout : -1; // Set timeout to -1 if waiting for confirmation

        // Check if the terminate signal was received
        pthread_mutex_lock(&terminateSignalMutex);
        if (errno == EINTR && terminateSignalReceived) {
            pthread_mutex_unlock(&terminateSignalMutex);
            return END_STATE;
        }
        pthread_mutex_unlock(&terminateSignalMutex);

        int ret = poll(fds, 2, pollTimeout); // wait for event
        if (ret < 0) {
            perror("poll");
            return ERROR_STATE;
        }
        // Retransmission of message if no confirmation received and timeout occurred
        if(ret == 0 && waiting_confirm == 1)
        {
            if (wait_confirm(sock, buffer2, totalLength2, (struct sockaddr*)server_addr, server_addr_len, timeout, retry, netOrderMessageID2)) {
                waiting_confirm = 0;
            } else {
                recieving = 1; // If the message was not confirmed after all retries, end the connection
                fprintf(stderr, "ERR:Failed to send message after %d retries\n", retry);
                return ERROR_STATE; // error state = 3
            }
        }

        if (fds[0].revents & POLLIN) {

            if (fgets(line, BUFFER_SIZE, stdin) == NULL) {
                if (feof(stdin)) {
                    fprintf(stderr, "ERR: EOF.\n");
                    return END_STATE;
                }
                fprintf(stderr, "ERR: EOF.\n");
                continue;
            }
            line[strcspn(line, "\n")] = 0; // Remove newline character

            if(strlen(line) == 0){
                fprintf(stderr, "ERR: line is empty.\n");

            }else{
                if (reply_recieved == 0) // If the server did not reply to the previous message
                {
                    if (strncmp(line, "/join ", 6) == 0) {
                        uint16_t netOrderMessageID = htons(messageID);
                        netOrderMessageID2 = netOrderMessageID;
                        int argsFilled = sscanf(line, "/join %s", channelID);
                        size_t totalLength = 1 + // Message type
                                             2 + // Message ID
                                             strlen(channelID) + 1 +
                                             strlen(Display_name) + 1;

                        char* message = (char*)malloc(totalLength);
                        if (!message) {
                            perror("Failed to allocate memory for auth message");
                            return ERROR_STATE;
                        }

                        size_t offset = 0;
                        message[offset++] = '\x03';


                        message[offset++] = (char)((netOrderMessageID >> 8) & 0xFF);
                        message[offset++] = (char)(netOrderMessageID & 0xFF);


                        strcpy(message + offset, channelID);
                        offset += strlen(channelID) + 1;


                        strcpy(message + offset, Display_name);
                        offset += strlen(Display_name) + 1;


                        memcpy(buffer2, message, totalLength);
                        totalLength2 = totalLength;

                        int send_join = sendto(sock, message, totalLength, 0, (struct sockaddr*)server_addr, server_addr_len);
                        if (send_join == -1) {
                            perror("Failed to send message");
                            free (message);
                            return ERROR_STATE;
                        }
                        free (message);
                        reply_recieved = 1;
                        messageID += 0x0001;
                        waiting_confirm = 1;
                    } else if (strncmp(line, "/rename ", 8) == 0) {
                        sscanf(line, "/rename %20s", newDisplayName);


                        if(!Check_Displayname(newDisplayName)) {
                            fprintf(stderr, "ERR: invalid rename.\n");

                        }else {
                            // Copy the new display name to the global variable
                            strncpy(Display_name, newDisplayName, MAX_DISPLAY_NAME_LENGTH);
                            Display_name[MAX_DISPLAY_NAME_LENGTH] = '\0'; // Add null terminator

                        }


                    }
                    else if(strncmp(line, "/help ", 8) == 0){
                        handle_help();

                    }
                    else { // sending message
                        uint16_t netOrderMessageID = htons(messageID);
                        netOrderMessageID2 = netOrderMessageID;
                        size_t totalLength = 1 + // Message type
                                             2 + // Message ID
                                             strlen(channelID) + 1 +
                                             strlen(Display_name) + 1
                                             + strlen(line) + 1;

                        char* message = (char*)malloc(totalLength);
                        if (!message) {
                            perror("Failed to allocate memory for auth message");
                            return ERROR_STATE;
                        }

                        size_t offset = 0;
                        message[offset++] = '\x04';


                        message[offset++] = (char)((netOrderMessageID >> 8) & 0xFF);
                        message[offset++] = (char)(netOrderMessageID & 0xFF);


                        strcpy(message + offset, Display_name);
                        offset += strlen(Display_name) + 1;


                        strcpy(message + offset, line);
                        offset += strlen(line) + 1;

                        memcpy(buffer2, message, totalLength);
                        totalLength2 = totalLength;


                        int send_msg = sendto(sock, message, totalLength, 0, (struct sockaddr*)server_addr, server_addr_len);
                        if (send_msg == -1) {
                            perror("Failed to send message");
                            free (message);
                            return ERROR_STATE;
                        }
                        printf("%s: %s\n", Display_name, line);
                        free (message);
                        waiting_confirm = 1;
                        messageID += 0x0001;



                    }
                }

            }


        }

        if (fds[1].revents & POLLIN) { // Read from the server
            int recv_reply = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *) server_addr,
                                      &server_addr_len);
            if (recv_reply == -1) {
                perror("Failed to receive message");
                return ERROR_STATE;
            }

            if(buffer[0] == 0x01) // reply
            {
                uint16_t receivedMessageID = (buffer[1] << 8) | buffer[2];

                size_t totalLength = 1 + // Message type
                                     2;   // Message ID
                char* message = (char*)malloc(totalLength);
                size_t offset = 0;
                message[offset++] = '\x00'; // Confirm message type

                message[offset++] = (char)((receivedMessageID >> 8) & 0xFF);
                message[offset++] = (char)(receivedMessageID & 0xFF);

                char* content_buffer = (char*)malloc(BUFFER_SIZE);
                if(!content_buffer){
                    perror("Failed to allocate memory for content buffer");
                    return ERROR_STATE;
                }
                if(buffer[3] == 0x01) // If result is OK
                {
                    int j = 0;
                    for (int i = 6; buffer[i] != '\0'; i++, j++) {
                        content_buffer[j] += buffer[i];
                    }
                    printf("Success: %s\n", content_buffer);


                }else{
                    int j = 0;
                    for (int i = 6; buffer[i] != '\0'; i++, j++) {
                        content_buffer[j] += buffer[i];
                    }
                    printf("Failure: %s\n", content_buffer);

                }
                free(content_buffer);


                int send_confirm = sendto(sock, message, totalLength, 0, (struct sockaddr*)server_addr, server_addr_len);
                if (send_confirm == -1) {
                    perror("Failed to send message");
                    free(message);
                    return ERROR_STATE;
                }
                free(message);
                reply_recieved = 0; // Received reply and can send another message
                recieving = 0; // Continue receiving messages

            }
            else if(buffer[0] == 0x04) // message
            {
                uint16_t receivedMessageID = (buffer[1] << 8) | buffer[2];
                size_t totalLength = 1 + // Message type
                                     2;   // Message ID
                char* message = (char*)malloc(totalLength);
                size_t offset = 0;
                message[offset++] = '\x00'; // Confirm message type

                message[offset++] = (char)((receivedMessageID >> 8) & 0xFF);
                message[offset++] = (char)(receivedMessageID & 0xFF);


                int send_confirm = sendto(sock, message, totalLength, 0, (struct sockaddr*)server_addr, server_addr_len);
                if (send_confirm == -1) {
                    perror("Failed to send message");
                    free(message);
                    return ERROR_STATE;
                }
                free(message);
                recieving = 0;
                // Print the message from server
                char* content_buffer = (char*)malloc(BUFFER_SIZE);
                char* name =(char*)malloc(BUFFER_SIZE);
                if(!content_buffer || !name){
                    perror("Failed to allocate memory for content buffer");
                    return ERROR_STATE;
                }
                if(buffer[0] == 0x04)
                {
                    int i, j;
                    for (i = 3, j = 0; buffer[i] != '\0' && buffer[i] != ' '; i++, j++) {
                        name[j] = buffer[i];
                    }
                    name[j] = '\0';

                    i++;


                    for (j = 0; buffer[i] != '\0'; i++, j++) {
                        content_buffer[j] = buffer[i];
                    }
                    content_buffer[j] = '\0';

                    printf("%s: %s\n", name, content_buffer);

                }
                free(name);
                free(content_buffer);

            }else if((unsigned char)buffer[0] == 0xFE) // error
            {

                uint16_t receivedMessageID = (buffer[1] << 8) | buffer[2];
                size_t totalLength = 1 + // Message type
                                     2;   // Message ID
                char* message = (char*)malloc(totalLength);
                size_t offset = 0;
                message[offset++] = '\x00'; // Confirm message type

                message[offset++] = (char)((receivedMessageID >> 8) & 0xFF);
                message[offset++] = (char)(receivedMessageID & 0xFF);


                int send_confirm_error = sendto(sock, message, totalLength, 0, (struct sockaddr*)server_addr, server_addr_len);
                if (send_confirm_error == -1) {
                    perror("Failed to send message");
                    free(message);
                    return ERROR_STATE;
                }
                free(message);
            }
            else if((unsigned char)buffer[0] == 0xFF)
            {
                uint16_t receivedMessageID = (buffer[1] << 8) | buffer[2];
                size_t totalLength = 1 + // Message type
                                     2;   // Message ID
                char* message = (char*)malloc(totalLength);
                size_t offset = 0;
                message[offset++] = '\x00'; // Confirm message type

                message[offset++] = (char)((receivedMessageID >> 8) & 0xFF);
                message[offset++] = (char)(receivedMessageID & 0xFF);


                int send_confirm_bye = sendto(sock, message, totalLength, 0, (struct sockaddr*)server_addr, server_addr_len);
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
                uint16_t receivedMessageID = (buffer[1] << 8) | buffer[2];
                waiting_confirm = 0;
            }
            else{
                fprintf(stderr, "ERR: unknown message type.\n");
            }
        }

    }

}

int End_state(int sock, struct sockaddr_in* server_addr, socklen_t server_addr_len, uint8_t retry, uint16_t timeout){
    uint16_t netOrderMessageID = htons(messageID);
    size_t totalLength = 1 +
                         2;


    char* message = (char*)malloc(totalLength);
    if (!message) {
        perror("Failed to allocate memory for auth message");
        return ERROR_STATE;
    }

    size_t offset = 0;
    message[offset++] = '\xFF'; // BYE type


    message[offset++] = (char)((netOrderMessageID >> 8) & 0xFF);
    message[offset++] = (char)(netOrderMessageID & 0xFF);




    wait_confirm(sock, message, totalLength, (struct sockaddr*)server_addr, server_addr_len, timeout, retry, netOrderMessageID);
    free (message);
    close(sock);
    exit(0);
}

int Error_state(int sock, struct sockaddr_in* server_addr, socklen_t server_addr_len, uint8_t retry, uint16_t timeout){
    char line[BUFFER_SIZE] = "ERROR";

    uint16_t netOrderMessageID = htons(messageID);
    size_t totalLength = 1 + // ERROR Message type
                         2+ // Message ID
                         strlen(Display_name) + 1
                         + strlen(line) + 1;


    char* message = (char*)malloc(totalLength);
    if (!message) {
        perror("Failed to allocate memory for auth message");
        return ERROR_STATE;
    }

    size_t offset = 0;
    message[offset++] = '\xFE';

    message[offset++] = (char)((netOrderMessageID >> 8) & 0xFF);
    message[offset++] = (char)(netOrderMessageID & 0xFF);
    strcpy(message + offset, Display_name);
    offset += strlen(Display_name) + 1;
    strcpy(message + offset, line);
    offset += strlen(line) + 1;
    wait_confirm(sock, message, totalLength, (struct sockaddr*)server_addr, server_addr_len, timeout, retry, netOrderMessageID);
    free (message);
    messageID += 0x0001;
    return END_STATE;
}




void udp_client() {
    int sock;
    struct sockaddr_in server_addr;
    struct hostent *he;

    if ((he = gethostbyname(config.server_ip)) == NULL) // get the host info
    {
        herror("gethostbyname");
        exit(EXIT_FAILURE);
    }

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config.server_port);
    server_addr.sin_addr = *((struct in_addr *)he->h_addr);


    State state = START_STATE;
    uint16_t timeout = 25000;
    uint8_t retry = 3;

    while(1) {
        switch (state) {
            case START_STATE: {
                state = Start_state(sock, &server_addr, sizeof(server_addr), retry, timeout );

                break;
            }

            case AUTH_STATE: {

                state = Auth_state(sock, &server_addr, sizeof(server_addr), retry, timeout);
                break;
            }

            case OPEN_STATE: {

                state = Open_state(sock, &server_addr, sizeof(server_addr), retry, timeout);
                break;
            }

            case ERROR_STATE: {

                state = Error_state(sock, &server_addr, sizeof(server_addr), retry, timeout);
                break;
            }

            case END_STATE: {

                state = End_state(sock, &server_addr, sizeof(server_addr), retry, timeout);
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
    }
    //
    if (config.server_ip == NULL || strcmp(config.server_ip, "") == 0) {
        fprintf(stderr, "Error: bad IP\n");
        exit(EXIT_FAILURE);
    }

    if(config.udp_retries < 0 || config.udp_timeout < 0){
        fprintf(stderr, "Error: bad number of retransmission or timeout\n");
        exit(EXIT_FAILURE);
    }


    // Check protocol
    if (strcmp(config.protocol, "tcp") == 0) {
        tcp_client();
        //
    } else if (strcmp(config.protocol, "udp") == 0) {
        udp_client();
        //
    } else {
        fprintf(stderr, "Error: bad protocol\n");
        exit(EXIT_FAILURE);
    }
}





