/**
 * Nonstop Networking
 * CS 241 - Spring 2019
 */
#pragma once
#include <stddef.h>
#include <sys/types.h>
#define MESSAGE_SIZE_DIGITS sizeof(size_t)

#define LOG(...)                      \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n");        \
    } while (0);

typedef enum { GET, PUT, DELETE, LIST, V_UNKNOWN } verb;

void generate_and_send_client_request(verb method, const char* remote_filename, const char* local_filename, int socketfd);
void read_from_server(int socketfd);
ssize_t read_all_from_socket(int socket, char *buffer, size_t count);
ssize_t write_message_size(size_t size, int socket);
ssize_t write_all_to_socket(int socket, const char *buffer, size_t count);
ssize_t read_one_line_from_server(int socketfd, char* buffer);
