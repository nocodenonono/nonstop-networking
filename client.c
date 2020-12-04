/**
 * Nonstop Networking
 * CS 241 - Spring 2019
 */
#include "common.h"
#include "format.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#define MESSAGE_SIZE_DIGITS sizeof(size_t)

char **parse_args(int argc, char **argv);
verb check_args(char **args);

int connect_to_server(const char *host, const char *port) {
    int socketfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(socketfd != -1);
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    int err = getaddrinfo(host, port, &hints, &result);
    if (err != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        freeaddrinfo(result);
        close(socketfd);
        exit(EXIT_FAILURE);
    }

    err = connect(socketfd, result->ai_addr, result->ai_addrlen);
    if (err == -1) {
        perror(NULL);
        freeaddrinfo(result);
        close(socketfd);
        exit(1);
    }
    freeaddrinfo(result);
    return socketfd;
}

ssize_t get_message_size(int socket) {
    size_t size;
    ssize_t read_bytes =
        read_all_from_socket(socket, (char *)&size, MESSAGE_SIZE_DIGITS);
    if (read_bytes == 0 || read_bytes == -1)
        return read_bytes;

    return (ssize_t) size;
}


int main(int argc, char **argv) {
    // Good luck!
    char** args = parse_args(argc, argv);

    if (!args) {
        print_client_usage();
        free(args);
        exit(1);
    }

    char* host = args[0];
    char* port = args[1];
    char* remote_filename = args[3]; // might be NULL
    char* local_filename = args[4]; // might be NULL
    free(args);
    verb method = check_args(argv);

    int server_socket = connect_to_server(host, port);
    generate_and_send_client_request(method, remote_filename, local_filename, server_socket);
    read_from_server(server_socket); // handles "OK" and "ERROR"

    char* buffer = NULL;

    if (method == GET) {
        ssize_t file_size = get_message_size(server_socket);
        buffer = calloc(1, file_size + 1);
        ssize_t bytes_read = read_all_from_socket(server_socket, buffer, file_size);
        if (bytes_read == 0) {
            print_too_little_data();
            file_size = strlen(buffer); // we recieve less than file_size data and we calloc first.
        }

        int local_file = open(local_filename, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG);
        write_all_to_socket(local_file, buffer, file_size);

        if (read_all_from_socket(server_socket, buffer, 1) > 0)
            print_received_too_much_data();

        free(buffer);
    } else if (method == DELETE || method == PUT) {
        print_success();
    } else if (method == LIST) {
        ssize_t file_size = get_message_size(server_socket);
        buffer = calloc(1, file_size + 1);
        ssize_t bytes_read = read_all_from_socket(server_socket, buffer, file_size);
        if (bytes_read == 0) {
            print_too_little_data();
            file_size = strlen(buffer); // we recieve less than file_size data and we calloc first.
        }

        fprintf(stdout, "%s", buffer);

        if (read_all_from_socket(server_socket, buffer, 1) > 0)
            print_received_too_much_data();

        free(buffer);
    }

    return 0;
}

/**
 * Given commandline argc and argv, parses argv.
 *
 * argc argc from main()
 * argv argv from main()
 *
 * Returns char* array in form of {host, port, method, remote, local, NULL}
 * where `method` is ALL CAPS
 */
char **parse_args(int argc, char **argv) {
    if (argc < 3) {
        return NULL;
    }

    char *host = strtok(argv[1], ":");
    char *port = strtok(NULL, ":");
    if (port == NULL) {
        return NULL;
    }

    char **args = calloc(1, 6 * sizeof(char *));
    args[0] = host;
    args[1] = port;
    args[2] = argv[2];
    char *temp = args[2];
    while (*temp) {
        *temp = toupper((unsigned char)*temp);
        temp++;
    }
    if (argc > 3) {
        args[3] = argv[3];
    }
    if (argc > 4) {
        args[4] = argv[4];
    }

    return args;
}

/**
 * Validates args to program.  If `args` are not valid, help information for the
 * program is printed.
 *
 * args     arguments to parse
 *
 * Returns a verb which corresponds to the request method
 */
verb check_args(char **args) {
    if (args == NULL) {
        print_client_usage();
        exit(1);
    }

    char *command = args[2];

    if (strcmp(command, "LIST") == 0) {
        return LIST;
    }

    if (strcmp(command, "GET") == 0) {
        if (args[3] != NULL && args[4] != NULL) {
            return GET;
        }
        print_client_help();
        exit(1);
    }

    if (strcmp(command, "DELETE") == 0) {
        if (args[3] != NULL) {
            return DELETE;
        }
        print_client_help();
        exit(1);
    }

    if (strcmp(command, "PUT") == 0) {
        if (args[3] == NULL || args[4] == NULL) {
            print_client_help();
            exit(1);
        }
        return PUT;
    }

    // Not a valid Method
    print_client_help();
    exit(1);
}

