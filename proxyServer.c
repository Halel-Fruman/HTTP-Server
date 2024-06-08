#include "threadpool.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_REQUEST_LEN 2048
#define MAX_FILTER_LEN 1024
#define MAX_ERROR_LEN 1024
#define INET_ADDRSTRLEN 16 // Maximum length of IPv4 address string representation
#define CHUNK_SIZE 256
#define MAX_PORT 65535


typedef struct {
    char **hosts;
    char **ips;
    int num_hosts;
    int num_ips;
} FilterInfo;

typedef struct {
    struct sockaddr_in sockinfo;
    int client_socket;
    int port;
    FilterInfo *filter_info;
} Connection;

// Global variable to hold filter information
FilterInfo global_filter_info;

void initialize_filter_info(FILE *fp) {


    char line[MAX_FILTER_LEN];
    while (fgets(line, sizeof(line), fp) != NULL) {
        // Trim trailing newline character
        size_t len = strlen(line);
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }


        // Check if the line represents an IP address or a host name
        if (isdigit(line[0])) {
            // Line represents an IP address
            global_filter_info.ips = realloc(global_filter_info.ips,
                                             (global_filter_info.num_ips + 1) * sizeof(char *));
            global_filter_info.ips[global_filter_info.num_ips] = strdup(line);
            global_filter_info.num_ips++;
        } else {
            // Line represents a host name
            global_filter_info.hosts = realloc(global_filter_info.hosts,
                                               (global_filter_info.num_hosts + 1) * sizeof(char *));
            global_filter_info.hosts[global_filter_info.num_hosts] = strdup(line);
            global_filter_info.num_hosts++;
        }
    }

}


// Function to free memory allocated for FilterInfo
void free_filter_info() {
    for (int i = 0; i < global_filter_info.num_hosts; i++) {
        free(global_filter_info.hosts[i]);
    }
    free(global_filter_info.hosts);
    for (int i = 0; i < global_filter_info.num_ips; i++) {
        free(global_filter_info.ips[i]);
    }
    free(global_filter_info.ips);
}


void generate_error_response(int code, char *header, char *body, char *response_buffer,int client) {
    fprintf(stderr, "Generating error response: %d %s\n", code, header);  // Log the type of error being handled

    // Get current date and time in GMT format
    time_t raw_time;
    struct tm *time_info;
    char date_time[MAX_ERROR_LEN];

    time(&raw_time);
    time_info = gmtime(&raw_time);
    strftime(date_time, sizeof(date_time), "%a, %d %b %Y %H:%M:%S GMT", time_info);

    // Calculate the content length (excluding HTTP header)

    char html[MAX_ERROR_LEN];
    snprintf(html, MAX_ERROR_LEN, "<HTML><HEAD><TITLE>%d %s</TITLE></HEAD>\r\n"
                                  "<BODY><H4>%d %s</H4>\r\n"
                                  "%s.\r\n"
                                  "</BODY></HTML>", code, header, code, header, body);
    size_t body_length = strlen(html);
    // Construct the error response
    int bytes_written = snprintf(response_buffer, MAX_ERROR_LEN,
                                 "HTTP/1.1 %d %s\r\n"
                                 "Server: webserver/1.0\r\n"
                                 "Date: %s\r\n"
                                 "Content-Type: text/html\r\n"
                                 "Content-Length: %zu\r\n"
                                 "Connection: close\r\n"
                                 "\r\n"
                                 "%s",
                                 code, header, date_time, body_length, html);

    // Check for buffer overflow
    if (bytes_written < 0 || bytes_written >= MAX_ERROR_LEN) {
        fprintf(stderr, "Error: Insufficient buffer size for generating error response\n");
        exit(EXIT_FAILURE);
    }
    send(client, response_buffer, strlen(response_buffer), 0);
    fprintf(stderr, "Error response generated successfully and sent.\n");  // Confirm successful generation


}

void parse_host(const char *host, char *hostname, int *port) {
    // Find the position of the colon (if present)
    char *colon_ptr = strchr(host, ':');
    if (colon_ptr != NULL) {
        // Port number is specified
        *port = atoi(colon_ptr + 1);
        strncpy(hostname, host, colon_ptr - host);
        hostname[colon_ptr - host] = '\0'; // Null-terminate the hostname
    } else {
        // Port number is not specified, default to port 80
        *port = 80;
        strcpy(hostname, host);
    }
}


int is_blocked(Connection *conn, const char *host) {
    // Check against filter_info hosts
    for (int i = 0; i < conn->filter_info->num_hosts; i++) {
        if (strcmp(host, conn->filter_info->hosts[i]) == 0) {
            return 1; // Blocked
        }
    }

    // Convert host IP address to string
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) {
        // Error resolving host
        return 0; // Not blocked
    }

    char host_ip[INET_ADDRSTRLEN];
    struct sockaddr_in *host_addr = (struct sockaddr_in *) res->ai_addr;
    inet_ntop(AF_INET, &(host_addr->sin_addr), host_ip, INET_ADDRSTRLEN);

    // Check against filter_info IPs and subnets
    for (int i = 0; i < conn->filter_info->num_ips; i++) {
        char *filter_ip = strdup(conn->filter_info->ips[i]);
        char *slash_pos = strchr(filter_ip, '/');
        if (slash_pos != NULL) {
            // Subnet rule (IP address with prefix length)
            *slash_pos = '\0'; // Separate IP address and prefix length
            char *subnet_ip = filter_ip;
            char *prefix_length_str = slash_pos + 1;
            int prefix_length = atoi(prefix_length_str);

            // Convert subnet IP address string to binary form
            struct sockaddr_in subnet_addr;
            if (inet_pton(AF_INET, subnet_ip, &subnet_addr.sin_addr) != 1) {
                // Invalid IP address format
                continue; // Skip to the next filter IP
            }

            // Calculate the subnet mask
            uint32_t mask = htonl(~((1 << (32 - prefix_length)) - 1));

            // Convert host IP address string from dotted-decimal to binary form
            struct in_addr host_ip_addr;
            if (inet_pton(AF_INET, host_ip, &host_ip_addr) != 1) {
                // Invalid host IP address format
                continue; // Skip to the next filter IP
            }

            // Apply the mask to the host address and the subnet IP address
            struct in_addr masked_host_addr;
            struct in_addr masked_subnet_addr;
            masked_host_addr.s_addr = host_addr->sin_addr.s_addr & mask;
            masked_subnet_addr.s_addr = subnet_addr.sin_addr.s_addr & mask;

            if (masked_host_addr.s_addr == masked_subnet_addr.s_addr) {
                freeaddrinfo(res);
                free(filter_ip);
                return 1; // Blocked
            }
        } else {
            // Single IP address rule
            if (strcmp(host_ip, filter_ip) == 0) {
                freeaddrinfo(res);
                free(filter_ip);
                return 1; // Blocked
            }
        }
        free(filter_ip);
    }

    freeaddrinfo(res);
    return 0; // Not blocked
}


void handle_connection(void *arg);


int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: proxyserver <port> <pool-size> <max-number-of-request> <filter>");
        exit(EXIT_FAILURE);
    }
    int port = atoi(argv[1]);
    int pool_size = atoi(argv[2]);
    int max_requests = atoi(argv[3]);
    char *filter_file = argv[4];

    FILE *fp = fopen(filter_file, "r");
    if (fp == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }
    initialize_filter_info(fp);

    // Create thread pool

    threadpool *pool = create_threadpool(pool_size);
    if (pool==NULL||port<=0||port>MAX_PORT)
    {free_filter_info();
        fprintf(stderr, "Usage: proxyserver <port> <pool-size> <max-number-of-request> <filter>");
        exit(EXIT_FAILURE);

    }
    // Create a socket
    int wsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (wsock == -1) {
        free_filter_info();
        destroy_threadpool(pool);
        perror("error: socket");
        exit(EXIT_FAILURE);
    }



    // Bind the socket
    struct sockaddr_in serverinfo;
    memset(&serverinfo, 0, sizeof(struct sockaddr_in));
    serverinfo.sin_family = AF_INET;
    serverinfo.sin_addr.s_addr = htonl(INADDR_ANY);
    serverinfo.sin_port = htons(port);


    if (bind(wsock, (struct sockaddr *) &serverinfo, sizeof(struct sockaddr_in)) == -1) {
        close(wsock);
        free_filter_info();
        fclose(fp);
        destroy_threadpool(pool);
        perror("error: bind");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(wsock, 10) == -1) {
        close(wsock);
        free_filter_info();
        fclose(fp);
        destroy_threadpool(pool);
        perror("error: listen");
        exit(EXIT_FAILURE);
    }


    int request_count = 0;

    // Accept connections and dispatch them to the thread pool
    while (request_count < max_requests) {
        // Create a connection struct to pass to the thread pool
        Connection *conn = (Connection *) malloc(sizeof(Connection));
        if (conn == NULL) {
            perror("error: malloc");
            close(wsock);
            free_filter_info();
            fclose(fp);
            destroy_threadpool(pool);
            exit(EXIT_FAILURE);
        }


        socklen_t client_len = sizeof(conn->sockinfo);
        conn->client_socket = accept(wsock, (struct sockaddr *) &conn->sockinfo, &client_len);
        if (conn->client_socket == -1) {
            perror("error: accept");
            close(wsock);
            free_filter_info();
            fclose(fp);
            free(conn);
            destroy_threadpool(pool);
            exit(EXIT_FAILURE);
        }
        conn->filter_info = &global_filter_info;
        conn->port = port;

        // Dispatch the connection to the thread pool
        dispatch(pool, (dispatch_fn) handle_connection, (void *) conn);

        request_count++;

    }
    // Wait for all threads in the pool to finish
    destroy_threadpool(pool);
    free_filter_info();
    // Close the server socket
    close(wsock);
    fclose(fp);

    return 0;
}

void handle_connection(void *arg) {
    Connection *conn = (Connection *) arg;
    int client_socket = conn->client_socket;
    struct timeval tv = {15, 0};

    if (setsockopt(conn->client_socket, SOL_SOCKET, SO_RCVTIMEO, (char *) &tv, sizeof(struct timeval)) == -1) {
        perror("setsockopt");
        close(conn->client_socket);
        free(conn);
        return;
    }
    // Buffer for storing the request
    // Allocate memory for the initial request buffer
    char* request = (char*)malloc(MAX_REQUEST_LEN * sizeof(char));
    if (request == NULL) {
        // Handle allocation failure
        perror("Error allocating memory for request buffer");
        close(client_socket);
        free(conn);
        return;
    }

// Initialize the request buffer with zeros
    memset(request, 0, MAX_REQUEST_LEN);

// Keep track of the total bytes read and the current buffer size
    ssize_t total_bytes_read = 0;
    size_t buffer_size = MAX_REQUEST_LEN;

// Read the request from the client in a loop until all bytes are received
    while (1) {
        ssize_t bytes_read = read(client_socket, request + total_bytes_read, buffer_size - total_bytes_read - 1);
        if (bytes_read < 0) {
            if (errno == EAGAIN) {
                perror("timedOut");
            }
            // Handle read error
            close(client_socket);
            free(request);
            free(conn);
            return;
        } else if (bytes_read == 0) {
            // Connection closed by client
            close(client_socket);
            free(request);
            free(conn);
            return;
        }

        total_bytes_read += bytes_read;

        // Check if the entire request has been received
        if (total_bytes_read >= 4 && memcmp(request + total_bytes_read - 4, "\r\n\r\n", 4) == 0) {
            break;
        }

        // Check if more space is needed in the buffer
        if (total_bytes_read >= buffer_size - 1) {
            // Resize the buffer using realloc
            buffer_size += CHUNK_SIZE;
            char* temp = (char*)realloc(request, buffer_size * sizeof(char));
            if (temp == NULL) {
                // Handle realloc failure
                perror("Error reallocating memory for request buffer");
                close(client_socket);
                free(request);
                free(conn);
                return;
            }
            request = temp;
        }
    }

// Null-terminate the request string
    request[total_bytes_read] = '\0';

    int len = (int) strlen((request));

    char *org = (char *) malloc(buffer_size*sizeof(char) );
    memset(org, 0, buffer_size);
    strcpy(org, request );
    org[len] = '\0';

    // Parse the request to extract method, path, and protocol
    char *method = strtok(request, " \t\n");
    char *path = strtok(NULL, " \t\n");
    char *protocol = strtok(NULL, " \t\n");

    if (method == NULL ||path == NULL || protocol == NULL) {
        // Invalid request format
        char response[MAX_ERROR_LEN];
        generate_error_response(400, "Bad Request", "Bad Request", response,client_socket);
        close(client_socket);
        free(conn);
        free(org);
        free(request);
        return;
    }

  // Validate HTTP protocol version
    if (strcmp(protocol, "HTTP/1.0\r") != 0 && strcmp(protocol, "HTTP/1.1\r") != 0) {
        // Unsupported HTTP version
        char response[MAX_ERROR_LEN];
        generate_error_response(400, "Bad Request", "Bad Request", response,client_socket);
        close(client_socket);
        free(conn);
        free(org);
        free(request);
        return;
    }
    if ( strcmp(method, "GET") != 0) {
        // Unsupported method
        // Send a 501 Not Supported response
        char response[MAX_ERROR_LEN];
        generate_error_response(501, "Not supported", "Method is not supported", response,client_socket);
        close(client_socket);
        free(conn);
        free(org);
        free(request);
        return;
    }


    for (int i = 0; i < MAX_REQUEST_LEN; i++) {
        if (request[i] == '\0') {
            request[i] = ' '; // Replace null terminator with space
        }
    }
    request[len - 1] = '\0';

    // Find Host header
    char *host_header = strstr(request, "Host");
    if (host_header == NULL) {
        // Host header not found
        // Send a 400 Bad Request response
        char response[MAX_ERROR_LEN];
        generate_error_response(400, "Bad Request", "Bad Request", response,client_socket);
        close(client_socket);
        free(conn);
        free(org);
        free(request);
        return;
    }

    // Extract host name
    char *host = strtok(host_header + 6, " \t\n");
    if (host == NULL) {
        // Invalid host format
        // Send a 400 Bad Request response
        char response[MAX_ERROR_LEN];
        generate_error_response(400, "Bad Request", "Bad Request", response,client_socket);
        close(client_socket);
        free(conn);
        free(org);
        free(request);
        return;
    }
    host[strlen(host) - 1] = '\0';
    int port;
    char hostName[256];
    parse_host(host, hostName, &port);

    // Check against filter (Assuming filter logic is implemented elsewhere)
    if (is_blocked(conn, hostName)) {
        // Host is blocked
        char response[MAX_ERROR_LEN];
        generate_error_response(403, "Forbidden", "Access Denied", response,client_socket);
        close(client_socket);
        free(conn);
        free(org);
        free(request);
        return;
    }

    char *connection_header = strstr(org, "Connection:");
    if (connection_header != NULL) {
        // Case 1: "Connection: keep-alive"
        char *keep_alive = strstr(connection_header, "keep-alive");
        if (keep_alive != NULL) {
            // Replace "keep-alive" with "close"
            memcpy(keep_alive, "close", strlen("close"));
            // Remove extra characters ("alive")
            memset(keep_alive + strlen("close"), ' ', strlen("alive"));
        } else {
            // Case 2: "Connection: close" (do nothing)
            // You can add more cases if needed in the future
        }
    } else {
        // Case 3: No "Connection" header in the request
        // Add "Connection: close" to the request header
        char *end_of_request = strstr(org, "\r\n\r\n");
        if (end_of_request != NULL) {
            // Found the end of the request, add "Connection: close"
            sprintf(end_of_request + 2, "Connection: close\r\n\r\n");
        }
    }


    // Connect to the origin server
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("error: socket");
        close(client_socket);
        free(conn);
        free(org);
        free(request);
        return;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);//



    // Resolve hostname to IP address
    struct hostent *he;
    if ((he = gethostbyname(hostName)) == NULL) {
        char response[MAX_ERROR_LEN];
        generate_error_response(404, "Not Found", "File not found", response,client_socket);
        herror("gethostbyname");
        close(server_socket);
        close(client_socket);
        free(conn);
        free(org);
        free(request);
        return;

    }
    memcpy(&server_addr.sin_addr.s_addr, he->h_addr, he->h_length);
    // Connect to the server
    if (connect(server_socket, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("error: connect");
        char response[MAX_ERROR_LEN];
        generate_error_response(500, "Internal Server Error", "Some server side error", response,client_socket);
        close(server_socket);
        close(client_socket);
        free(conn);
        free(request);
        return;
    }

    char *end_of_request = strstr(org, "\r\n\r\n");
    if (end_of_request != NULL) {
        // Found the end of the request, put a null terminator there
        end_of_request[4] = '\0';
    } else {
    }


    // Forward the request to the origin server
    if (send(server_socket, org, strlen(org), 0) == -1) {
        perror("error: send");
        char response[MAX_ERROR_LEN];
        generate_error_response(500, "Internal Server Error", "Some server side error.", response,client_socket);
        close(server_socket);
        close(client_socket);
        free(conn);
        free(org);
        free(request);
        return;
    }

    // Receive response from the origin server and forward it to the client
    unsigned char *response_buffer = (unsigned char *) malloc(MAX_REQUEST_LEN);
    if (response_buffer == NULL) {
        // Handle allocation failure
        perror("malloc");
        char response[MAX_ERROR_LEN];
        generate_error_response(500, "Internal Server Error", "Some server side error.", response,client_socket);
        close(server_socket);
        close(client_socket);
        free(conn);
        free(org);
        free(request);
        return;
    }
    buffer_size = MAX_REQUEST_LEN;
    ssize_t total_bytes_received = 0;
    ssize_t bytes_received;
    size_t bytes_sent_total = 0; // Initialize bytes_sent_total

    while ((bytes_received = recv(server_socket, response_buffer + total_bytes_received,
                                  buffer_size - total_bytes_received, 0)) > 0) {
        total_bytes_received += bytes_received;

        // Check if the buffer needs to be resized
        if (total_bytes_received >= buffer_size) {
            // Double the buffer size
            size_t new_size = buffer_size * 2;
            unsigned char *new_buffer = (unsigned char *) realloc(response_buffer, new_size);
            if (new_buffer == NULL) {
                // Handle realloc failure
                perror("malloc");
                char response[MAX_ERROR_LEN];
                generate_error_response(500, "Internal Server Error", "Some server side error.", response,client_socket);
                close(server_socket);
                close(client_socket);
                free(conn);
                free(org);
                free(request);
                return;
            }
            response_buffer = new_buffer;
            buffer_size = new_size;
        }

        // Forward the received data to the client
        ssize_t bytes_sent = send(client_socket, response_buffer + bytes_sent_total, bytes_received, 0);
        if (bytes_sent == -1) {
            perror("send");
            char response[MAX_ERROR_LEN];
            generate_error_response(500, "Internal Server Error", "Some server side error.", response,client_socket);
            close(server_socket);
            close(client_socket);
            free(conn);
            free(org);
            free(request);
            return;
        }
        bytes_sent_total += bytes_sent;
    }

    if (bytes_received < 0) {
        // Handle recv error
        perror("recv");
        char response[MAX_ERROR_LEN];
        generate_error_response(500, "Internal Server Error", "Some server side error.", response,client_socket);
        close(server_socket);
        close(client_socket);
        free(conn);
        free(org);
        free(request);
        return;
    }

// Free the allocated memory
    free(response_buffer);
    free(org);
    free(request);
    // Close the sockets and free memory
    close(server_socket);
    close(client_socket);
    free(conn);



}
