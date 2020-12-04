/**
 * Nonstop Networking
 * CS 241 - Spring 2019
 */
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include "format.h"

#define MAX_HEADER_LENGTH 1024
#define ERROR_SIZE 6
#define OK_SIZE 3
#define MAX_FIRST_LINE_REQUEST_SIZE 300

ssize_t write_message_size(size_t size, int socket) {
    // Your code here
    return write_all_to_socket(socket, (const char* ) &size, 8);
}

ssize_t read_all_from_socket(int socket, char *buffer, size_t count) {
    // Your Code Here
    size_t bytes_read = 0;
    while (bytes_read != count) {
        ssize_t res = read(socket, buffer + bytes_read, count - bytes_read);
        if (res == 0)
            return 0;
        else if (res > 0)
            bytes_read += res;
        else if (res == -1 && errno == EINTR)
            continue;
        else
            return -1;
    }

    return (ssize_t) bytes_read;
}

ssize_t write_all_to_socket(int socket, const char *buffer, size_t count) {
    // Your Code Here
    size_t bytes_write = 0;
    while (bytes_write != count) {
        ssize_t res = write(socket, buffer + bytes_write, count - bytes_write);
        if (res == 0)
            return 0;
        else if (res > 0)
            bytes_write += res;
        else if (res == -1 && errno == EINTR)
            continue;
        else
            return -1;
    }

    return (ssize_t) bytes_write;
}

/**
 * find size of file with error checking and exit
 */
size_t find_file_size(const char* filename) {
    struct stat buf;
    if (stat(filename, &buf) == -1) {
        perror(NULL);
        exit(1);
    }
    return (size_t) buf.st_size;
}

/**
 * generate corresponding client request.
 * needs to free the returen string.
 * exit if failed.
 */
void generate_and_send_client_request(verb method, const char* remote_filename, const char* local_filename, int socketfd) {
    char res[MAX_FIRST_LINE_REQUEST_SIZE];
    memset(res, 0, MAX_FIRST_LINE_REQUEST_SIZE);
    char* binary_data = NULL;

    // generate client request.
    if ( method == GET ) {
        snprintf(res, MAX_FIRST_LINE_REQUEST_SIZE, "GET %s\n", remote_filename);
    } else if ( method == PUT ) {
        snprintf(res, MAX_FIRST_LINE_REQUEST_SIZE, "PUT %s\n", remote_filename);
    } else if ( method == DELETE ) {
        snprintf(res, MAX_FIRST_LINE_REQUEST_SIZE, "DELETE %s\n", remote_filename);
    } else if ( method == LIST) {
        strcpy(res, "LIST\n");
    } else {
        close(socketfd);
        exit(1);
    }

    // write the request to the server.
    LOG("writting to the server...\n");
    ssize_t write_size = write_all_to_socket(socketfd, res, strlen(res));
    assert(write_size > 0);

    // if put, write file size and binary data to server as well.
    if ( method == PUT ) {
        size_t file_size = find_file_size(local_filename);
        write_message_size(file_size, socketfd);

        int fp = open(local_filename, O_RDONLY);
        binary_data = calloc(1, file_size);
        read_all_from_socket(fp, binary_data, file_size);
        LOG("file size is: %zu\n", file_size);
        write_all_to_socket(socketfd, binary_data, file_size);
        free(binary_data);
        binary_data = NULL;
        close(fp);
    }


    // shut down the write half of client.
    if ( shutdown(socketfd, SHUT_WR) )
        perror(NULL);
}

ssize_t read_one_line_from_server(int socketfd, char* buffer) {
    size_t bytes_read = 0;

    while (1) {
        int res = read(socketfd, buffer + bytes_read, 1);

        if (res == 0) {
            return 0;
        } else if (res > 0) {
            if (buffer[bytes_read] == '\n') {
                buffer[bytes_read] = '\0';
                break;
            }
            bytes_read++;
        } else if (res == -1 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }

    return (ssize_t) bytes_read;
}

void read_from_server(int socketfd) {
    LOG("parsing response...\n");
    char buffer[MAX_HEADER_LENGTH + 1];
    ssize_t first_line_size = read_one_line_from_server(socketfd, buffer);
    if (first_line_size <= 0) {
        print_invalid_response();
        close(socketfd);
        exit(1);
    }

    // ERROR\n from server
    if (!strcmp(buffer, "ERROR")) {
        read_one_line_from_server(socketfd, buffer);
        print_error_message(buffer);
        close(socketfd);
        exit(1);
    } else if (strcmp(buffer, "OK") != 0) {
        print_invalid_response();
        close(socketfd);
        exit(1);
    }
}
