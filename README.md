# **IPK Project 1**

## Description

This project is a client for a simple chat server. The client is written in C and is able to communicate with the server using either TCP or UDP. The client is able to send messages to the server and receive responses. The client is also able to handle errors and terminate the connection gracefully.
Behvaior of the client is described in the FSM diagram below.

![Alt text](https://git.fit.vutbr.cz/NESFIT/IPK-Projects-2024/media/branch/master/Project%201/diagrams/protocol_fsm_client.svg)

## Usage
```bash
./ipk24chat-client -t <tcp|udp> -s <server_ip> -p <port>
```

`Usage` : ./ipk24chat-client -t <tcp|udp> -s <server_ip> -p <port> [-d <timeout>] [-r <retries>]
```
Options:
-t <tcp|udp>       Transport protocol used for connection.
-s <server_ip>     Server IP address or hostname.
-p <port>          Server port (Default: 4567).
-d <timeout>       UDP confirmation timeout in milliseconds (Default: 250).
-r <retries>       Maximum number of UDP retransmissions (Default: 3).
-h                 Display this help message and exit.
```
## Implementation

The client is implemented in C and is divided into several functions. The main function is responsible for parsing command line arguments, checking their validity and calling the appropriate function.

### Main function

The main function first parses the command line arguments with the `getopt()` function. The arguments are checked for validity. The `-t` argument must be either `tcp` or `udp`. The `-s` argument must be a valid IP address or hostname. The `-p` argument must be a valid port number. The `-d` argument must be a positive integer. The `-r` argument must be a positive integer. If any of the arguments are invalid, the program prints an error message and exits with the code 1.

The main function then calls the appropriate function based on the transport protocol. If the transport protocol is `tcp`, the `tcp_client()` function is called. If the transport protocol is `udp`, the `udp_client()` function is called.

### TCP client
The TCP client first creates a socket with the `socket()` function. The client then finds the server with the `gethostbyname()` function and creates a structure `server` with the server's IP address and port number. The client then connects to the server with the `connect()` function.
Then the client operates in a loop. First, it gets input from the user with the `fgets()` function. The input is sent to the server with the `send()` function. The client then waits for a response from the server with the `recv()` function. The response is printed to the user. The loop have the same states as FSM diagram above. The client can be terminated by pressing `Ctrl+C`, which closes the socket, thus terminating the connection, and exits the program.

For handling responses from the server in the TCP mode was implemented `handle_response()` function. The function parse the response from the server and prints the appropriate message to the user. Also this function return integer value, which is used to determine if the client should continue in the loop or go to other state.

To handle input from a network socket and standard input (stdin) without blocking the program's execution was used `POLL`. 
Setup of `POLL` involves:
1. Creating a `struct pollfd` array with two elements, one for the network socket and one for stdin.
2. Setting the `fd` field of the network socket element to the socket file descriptor.
3. Setting the `events` field of the network socket element to `POLLIN`.
4. Setting the `fd` field of the stdin element to `0`.
5. Setting the `events` field of the stdin element to `POLLIN`.

`POLL` is called inside of the loop and waiting for the response from the server or input from the user. If the response is received, the `handle_response()` function is called. If the user inputs something, the input is sent to the server.

To find the server was used `gethosbyname()` function. The function returns a pointer to a `struct hostent` structure, which contains information about the server. The `struct hostent` structure contains the server's IP address and port number.

### UDP client
The UDP client use the same structure as the TCP client. The client first creates a socket with the `socket()` function. The client then finds the server with the `gethostbyname()` function and creates a structure `server` with the server's IP address and port number.
UDP client use FSM logic to switch between states. 

For checking stdin messages from user were implemented functions like `Check_username()` and others.

For avoiding packet duplication was used MessageID. MessageID is converting in network order using `htons()` function: `uint16_t networkOrderMessageID = htons(messageID)`.


For packet loss was implemented retransmission of the packet. The client sends the packet and waits for the response. If the response is not received within the timeout, the client resends the packet. The client resends the packet up to the maximum number of retries. If the response is not received after the maximum number of retries, the client return `ERROR_STATE`.
To avoid packet loss was implemented function `wait_confirm()`, which waits for the response from the server. The function uses `POLL` to wait for the response. If the response is received, the function returns  0. If the response is not received within the timeout, the function returns 1.


### Hostname Resolution
The client supports connecting to the server using a hostname, thanks to the `gethostbyname()` function for IPv4. This function resolves the server's hostname to its IP address, enabling the client to establish connections without requiring the server's IP address directly. 

### Graceful Shutdown
The client is designed to terminate gracefully in response to an interrupt signal (e.g., Ctrl+C). Upon receiving the signal, the client closes the socket, ensuring a proper shutdown of the connection with the server. For the implementation of signal handling was used `signal()` function.
### Error handling
Robust error and signal handling mechanisms are integral to the client's design. The client can handle various errors, such as invalid command-line arguments, connection failures, and data transmission errors, providing appropriate feedback to the user.



## Testing
For testing the ipk24-chat client, two methods were used, tailored to TCP and UDP protocols respectively. Testing was made manually by running the client and server on separate terminals and observing the interaction between them.
The client was tested on macos and linux operating systems.
### TCP Testing
TCP was testing using netcat utility. The server was started with the following command:
```bash
nc -4 -c -l -v 127.0.0.1 4567
```
The client was started with the following command:
```bash
./ipk24chat-client -t tcp -s 127.0.0.1 -p 4567
```
#### Examples of the client input and output are shown below:
```bash
/auth username secret Display_Name
Success: Auth success.
Display_Name: Hello
Server: Hello
Display_Name: bye
```
```bash
/auth Tom secret Tomik
Success: Auth success.
Tomik: Hello
Server: Hello
/join channel22
Success: Join success.
Server: Tomik has joined channel22.
Tomik: Bye
```
#### Examples from Wireshark:

Simple TCP conversation:
```bash
AUTH tom AS Tomik USING secret
                              REPLY OK IS Auth success.
                              MSG FROM Server IS Tomik joined default.
                              MSG FROM Server IS Tomik Hello
MSG FROM Tomik IS Hi
MSG FROM Tomik IS Bye
BYE
```
Bye message from client:
```bash
AUTH tom AS Tomik USING secret
                              REPLY OK IS Auth success.
BYE
```

### UDP Testing
For testing UDP was used servrer from [2]. The server was started with the following command:
```bash
 python3 ipk_server.py
```
The client was started with the following command:
```bash
./ipk24chat-client -t udp -s 127.0.0.1 -p 4567
```

#### Examples of the client input and output are shown below:
```bash
/auth a b Tim
Success: Hi, Tim, this is a successful REPLY message to your AUTH message id=0. You wanted to authenticate under the username a
Tim: Hi
Server: Hi, Tim! This is a reply MSG to your MSG id=256 content='Hi...' :)
/join channel2
Success: Hi, Tim, this is a successful REPLY message to your JOIN message id=512. You wanted to join the channel channel2
```

```bash
/auth user1 secret Kaja
Success: Hi, Kaja, this is a successful REPLY message to your AUTH message id=0. You wanted to authenticate under the username user1
Kaja: Bye
Server: Hi, Kaja! This is a reply MSG to your MSG id=256 content='Bye...' :) 
```

#### Compare MessageID and screenshot from Wireshark:
```bash
/auth user secret Max
Success: Hi, Max, this is a successful REPLY message to your AUTH message id=0. You wanted to authenticate under the username user
hi
Max: hi
Server: Hi, Max! This is a reply MSG to your MSG id=256 content='hi...' :)
```
![Example Image](messageID.png)
MessageIDs are correct.

#### Sending Bye from client and screenshot from Wireshark:
```bash
/auth user secret Kaja
Success: Hi, Kaja, this is a successful REPLY message to your AUTH message id=0. You wanted to authenticate under the username user
Ahoj
Kaja: Ahoj
Server: Hi, Kaja! This is a reply MSG to your MSG id=256 content='Ahoj...' :)
Ctrl + c
```
![Example Image](Bye.png)
Bye was send from client and server received it.

## References

[1]: DOLEJŠKA, Daniel. PK-Projects-2024/Project 1 [online]. 2024 [cit. 2024-04-01]. Dostupné z: https://git.fit.vutbr.cz/NESFIT/IPK-Projects-2024/src/branch/master/Project%201

[2]: Ipk_server.py [online]. 2024 [cit. 2024-04-01]. Available at: https://github.com/okurka12/ipk_proj1_livestream/blob/main/ipk_server.py

[3]: Beej's Guide to Network Programming: Using Internet Sockets [online]. 2023 [cit. 2024-04-01]. Available at: https://beej.us/guide/bgnet/html/. 