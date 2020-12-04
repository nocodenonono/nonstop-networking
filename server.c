/**
 * Nonstop Networking
 * CS 241 - Spring 2019
 */
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <assert.h>
#include "format.h"
#include "common.h"
#include "includes/dictionary.h"
#include "includes/vector.h"

#define MAX_IO_SIZE 1024
#define MAX_FILENAME_LEN 255
#define MAX_EVENTS 100
#define DIR_OFFSET 7 // xxxxxx/ total 7 bytes
#define ERROR_SIZE
#define MIN(a, b) (a < b ? a : b)

typedef enum { FIRST_LINE, SIZE, PROCESSING, PROCESSING2, FINISH, FAIL } state_t;

typedef struct client_info {
    state_t state ;
    verb method;
    char* filename;
    size_t offset;
    char* buffer;
    size_t file_size;
    int closed;
    FILE* fp;
}client_info_t;

static int epfd = 0;
static int serverSocket = 0;
static int endSession = 0;
static char* dir_name = NULL;
static vector* files = NULL;
static dictionary* connections = NULL;
static struct epoll_event event, events[MAX_EVENTS];

client_info_t* create_client_info() {
    client_info_t* ev = malloc(sizeof(client_info_t));
    ev->state = FIRST_LINE;
    ev->method = V_UNKNOWN;
    ev->offset = 0;
    ev->buffer = calloc(MAX_IO_SIZE, 1);
    ev->filename = NULL;
    ev->file_size = 0;
    ev->closed = 0;
    ev->fp = NULL;
    return ev;
}

void destroy_client_info(client_info_t* ev) {
    free(ev->buffer);
    free(ev->filename);
    if (ev->fp)
        fclose(ev->fp);
    free(ev);
}

void send_error_msg(int fd, const char* err_msg) {
    char* err = "ERROR\n";
    write_all_to_socket(fd, err, strlen(err));
    write_all_to_socket(fd, err_msg, strlen(err_msg));
}

ssize_t read_all_from_socket_server(int socket, char *buffer, size_t count) {
    // Your Code Here
    size_t bytes_read = 0;
    while (bytes_read < count) {
        ssize_t res = read(socket, buffer + bytes_read, count - bytes_read);
        if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
        else if (res > 0)
            bytes_read += res;
        else if (res == -1 && errno == EINTR)
            continue;
        else if (res == 0)
            return -2;
        else
            return -1;
    }
    // LOG("read %zu many bytes", bytes_read);
    return (ssize_t) bytes_read;
}

ssize_t get_message_size(int socket, client_info_t* client_info) {
    char* size = (char* ) &(client_info->file_size) + client_info->offset;
    ssize_t read_bytes =
        read_all_from_socket_server(socket, size, MESSAGE_SIZE_DIGITS - client_info->offset);
    if (read_bytes == 0 || read_bytes == -1)
        return read_bytes;

    client_info->offset += read_bytes;
    if (client_info->offset == MESSAGE_SIZE_DIGITS) {
        client_info->offset = 0;
        client_info->state = PROCESSING;
    }
    return client_info->offset;
}

ssize_t read_one_line_from_client(int socketfd, char* buffer, client_info_t* client_info) {
    while (1) {
        int res = read(socketfd, buffer + client_info->offset, 1);

        if (res == 0) {
            return -1;
        } else if (res > 0) {
            if (buffer[client_info->offset] == '\n') {
                buffer[client_info->offset] = '\0';
                client_info->offset = 0;
                client_info->state = SIZE;
                break;
            }
            client_info->offset++;
        } else if (res == -1 && errno == EINTR) {
            continue;
        } else if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        } else {
            return -1;
        }
    }

    return client_info->offset;
}

int delete_file(client_info_t* client_info) {
    char* target = client_info->filename + DIR_OFFSET; // I store path instead of filename
    for (size_t i = 0; i < vector_size(files); i++) {
        char* filename = (char* ) vector_get(files, i);
        if (!strcmp(filename, target)) {
            free(filename);
            vector_erase(files, i);
            if ( unlink((const char* )client_info->filename) == -1 ) {
                perror("unlink a file failed");
                return 0;
            }
            return 1;
        }
    }
    return 0;
}

int parse_client_request(int fd, client_info_t* client_info) {
    if (client_info->offset != 0)
        return 1;

    /* Get verb */
    char* command = strtok(client_info->buffer, " ");
    char* filename = strtok(NULL, " ");

    if (strcmp(command, "LIST") == 0)
        client_info->method = LIST;

    if (strcmp(command, "GET") == 0)
        client_info->method = GET;

    if (strcmp(command, "DELETE") == 0)
        client_info->method = DELETE;

    if (strcmp(command, "PUT") == 0)
        client_info->method = PUT;

    /* Bad request (malformed or nonexistent verb) */
    if (client_info->method == V_UNKNOWN) {
        send_error_msg(fd, err_bad_request);
        client_info->state = FAIL;
        return 0;
    }

    /* No such file (GET/DELETE on nonexistent file) */
    char* path = NULL;
    asprintf(&path, "%s/%s", dir_name, filename);
    if (client_info->method == GET || client_info->method == DELETE) {
        struct stat s;
        if ( stat(path, &s) != 0 ) {
            free(path);
            client_info->state = FAIL;
            send_error_msg(fd, err_no_such_file);
            return 0;
        }
        client_info->file_size = s.st_size;
    }
    client_info->filename = path;

    /* open file if PUT */
    if (client_info->method == PUT) {
        delete_file(client_info);
        FILE* fp = fopen(client_info->filename, "w+");
        if (!fp) {
            perror("fopen");
            client_info->state = FAIL;
            return 0;
        }
        client_info->fp = fp;
        void* target = (void*) (client_info->filename + DIR_OFFSET);
        vector_push_back(files, strdup(target));
    }

    /* open the file if GET */
    if (client_info->method == GET) {
        FILE* fp = fopen(client_info->filename, "r");
        if (!fp) {
            perror("fopen");
            client_info->state = FAIL;
            return 0;
        }
        client_info->fp = fp;
    }

    /* Done with parsing, now process data */
    if (client_info->method == PUT)
        client_info->state = SIZE;
    else
        client_info->state = PROCESSING;

    // LOG("successfully parsing request");
    return 0;
}

ssize_t send_file(int fd, client_info_t* client_info) {
    /* open local file */
    FILE* local = client_info->fp;
    int file_fd = fileno(local);
    /* read local file to buffer and write to client */
    while (1) {
        size_t count = MIN(MAX_IO_SIZE, client_info->file_size - client_info->offset);
        size_t read_bytes = read_all_from_socket_server(file_fd, client_info->buffer, count);
        ssize_t write_bytes = write_all_to_socket(fd, client_info->buffer, read_bytes);
        // assert(read_bytes == (size_t) write_bytes);
        // LOG("have sent %zu many bytes", client_info->offset);
        client_info->offset += write_bytes;
        if (client_info->offset == client_info->file_size) {
            client_info->state = FINISH;
            break;
        }

        if (write_bytes <= 0)
            break;
    }
    return client_info->offset;
}

void send_file_list(int fd, client_info_t* client_info) {
    size_t total_len = 0;
    size_t size = vector_size(files);
    char* file_list = calloc(1, 1);
    for (size_t i = 0; i < size; i++) {
        char* filename = (char*) vector_get(files, i);
        size_t filename_len = strlen(filename) + 1; // including the newline.
        file_list = realloc(file_list, filename_len + total_len + 1);
        char buffer[] = "\n";
        strcat(&file_list[total_len], filename);
        strcat(&file_list[total_len + filename_len - 1], buffer);
        total_len += filename_len;
    }
    write_message_size(total_len - 1, fd);
    write_all_to_socket(fd, file_list, total_len - 1); // not writing the last newline byte.
    free(file_list);
    client_info->state = FINISH;
}

void read_binary_data_from_client(int fd, client_info_t* client_info) {
    FILE* fp = client_info->fp;
    int file = fileno(fp);
    assert(fp);
    while (1) {
	if (client_info->offset == client_info->file_size)
	    break;

        size_t count = MIN(MAX_IO_SIZE, client_info->file_size - client_info->offset);
        ssize_t read_bytes = read_all_from_socket_server(fd, client_info->buffer, count);
        if (read_bytes == -2) {
            delete_file(client_info);
            print_too_little_data();
            send_error_msg(fd, err_bad_file_size);
            client_info->state = FAIL;
            return;
        }

        ssize_t write_bytes = write_all_to_socket(file, client_info->buffer, read_bytes);
        client_info->offset += write_bytes;

        if (read_bytes < (ssize_t) count) {
            break;
        }

        if (client_info->offset == client_info->file_size)
            break;
    }
    if (client_info->offset == client_info->file_size) {
        ssize_t ret = read_all_from_socket_server(fd, client_info->buffer, 1);
        if (ret > 0) {
            delete_file(client_info);
            print_received_too_much_data();
            send_error_msg(fd, err_bad_file_size);
            client_info->state = FAIL;
            return;
        }
        client_info->state = PROCESSING2;
    }
}

void send_ok(int fd) {
    char ok[] = "OK\n";
    write_all_to_socket(fd, ok, strlen(ok));
}

int change_to_epoll_write(int fd) {
    event.data.fd = fd;
    event.events = EPOLLOUT | EPOLLET;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &event) == -1) {
        perror("epoll_ctl");
        return -1;
    }
    return 0;
}


void process_client_request(int fd) {
    client_info_t* client_info = (client_info_t*) dictionary_get(connections, (void*) (size_t) fd);

    /* parse header if not complete or fail, return */
    if (client_info->state == FIRST_LINE) {
        ssize_t ret = read_one_line_from_client(fd, client_info->buffer, client_info);
        // LOG("processing header");
        if (ret < 0) {
            // LOG("processing header failed");
            client_info->state = FAIL;
            goto DONE;
        }
        if ( parse_client_request(fd, client_info) )
            return;
    }

    /* read size if PUT */
    if (client_info->state == SIZE) {
        get_message_size(fd, client_info);
        // if (!client_info->offset)
            // LOG("client is sending file with size : %zu", client_info->file_size);
    }

    /* Done with parsing, process data */
    if (client_info->state == PROCESSING) {
	if (client_info->method != PUT) {
            if (change_to_epoll_write(fd))
                return;
        }
        switch (client_info->method) {
        case GET:
            send_ok(fd);
            write_message_size(client_info->file_size, fd);
            client_info->state = PROCESSING2;
            break;
        case PUT:
            read_binary_data_from_client(fd, client_info);
            break;
        case DELETE:
            delete_file(client_info);
            client_info->state = PROCESSING2;
            break;
        case LIST:
            // LOG("sending ok.....");
            send_ok(fd);
            client_info->state = PROCESSING2;
            break;
        default:
            return;
        }
    }

    if (client_info->state == PROCESSING2) {
        // LOG("Entering second stage of processing......");
	if (client_info->method == PUT) {
            if (change_to_epoll_write(fd))
                return;
        }
        switch (client_info->method) {
        case GET:
            send_file(fd, client_info);
            break;
        case PUT:
            send_ok(fd);
            client_info->state = FINISH;
            break;
        case DELETE:
            send_ok(fd);
            client_info->state = FINISH;
            break;
        case LIST:
            // LOG("sending list......");
            send_file_list(fd, client_info);
            client_info->state = FINISH;
            break;
        default:
            return;
        }
    }

    DONE:
    if (client_info->state == FINISH || client_info->state == FAIL) {
        if (!client_info->closed) {
            if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL) == -1)
                perror("epoll delete");

            if (shutdown(fd, SHUT_RDWR) != 0)
                perror("shutdown");

            client_info->closed = 1;
        }
    }
}

void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl():");
        return;
    }
     if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl():");
        return ;
    }
}

void run_server(char* port) {
    int socketfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int optval = 1;
    int err = setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if (err == -1) {
        perror(NULL);
        close(socketfd);
        return;
    }

    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    err = getaddrinfo(NULL, port, &hints, &result);
    if (err != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
	    freeaddrinfo(result);
        close(socketfd);
        return;
    }

    err = bind(socketfd, result->ai_addr, result->ai_addrlen);
    if (err != 0) {
        perror(NULL);
	    freeaddrinfo(result);
        close(socketfd);
        return;
    }

    err = listen(socketfd, 128);
    if (err != 0) {
        perror(NULL);
	    freeaddrinfo(result);
        close(socketfd);
        return;
    }

    freeaddrinfo(result);
    serverSocket = socketfd;
    endSession = 0;

    epfd = epoll_create(1);
    if (epfd == -1) {
        perror("epoll_create failed");
        close(socketfd);
        return;
    }

    event.events = EPOLLIN | EPOLLET;  // EPOLLIN==read, EPOLLOUT==write
    event.data.fd = serverSocket;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, serverSocket, &event) == -1) {
        perror("epll_ctl_add");
        close(epfd);
        close(socketfd);
        return;
    }


    while (!endSession) {
        int nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
        for (int n = 0; n < nfds; n++) {
            int fd = events[n].data.fd;
	    uint32_t flag = events[n].events;
	    if ( (flag & EPOLLERR) || (flag & EPOLLRDHUP) ) {
		close(fd);
		continue;
            }
            if (fd == serverSocket) {
                int client_fd = 0;
                while ( (client_fd = accept(serverSocket, NULL, NULL)) != -1 ) {
                // int client_fd = accept(serverSocket, NULL, NULL);
                // if (client_fd == -1) {
                //     perror("accept");
                //     continue;
                // }

                set_nonblocking(client_fd);
                event.data.fd = client_fd;
                event.events = EPOLLIN | EPOLLET;
                if (epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &event) == -1) {
                    perror("epll_ctl_add");
		    break;
		}

                client_info_t* ev = create_client_info();
                dictionary_set(connections, (void*) (size_t) client_fd, (void*) ev);
                }
            } else {
                process_client_request(fd);
            }
        }
    }

}

void close_server() {
    endSession = 1;
    fprintf(stdout,"closing server\n");
}

void sigpipe() {
    return;
}

void clean_up() {
    if (shutdown(serverSocket, SHUT_RDWR) != 0) {
        perror("shutdown():");
    }
    close(serverSocket);

    size_t i = 0;
    for (i = 0; i < vector_size(files); i++) {
        char* filename = (char* ) vector_get(files, i);
        size_t size = strlen(filename) + DIR_OFFSET + 2;
        char path[size];
        snprintf(path, size, "%s/%s", dir_name, filename);
        if (unlink((const char* ) path) == -1)
            perror("unlink");
        free(filename);
    }

    if (rmdir((const char* ) dir_name) == -1) {
        perror("rmdir()");
    }

    vector_destroy(files);

    vector* keys = dictionary_keys(connections);
    for (i = 0; i < vector_size(keys); i++) {
        size_t client_id = (size_t) vector_get(keys, i);
        client_info_t* client_info = (client_info_t* ) dictionary_get(connections, (void*) client_id);
        if (!client_info->closed) {
            if (shutdown(client_id, SHUT_RDWR) != 0) {
                perror("shutdown(): ");
            }
            close(client_id);
        }
        destroy_client_info(client_info);
    }
    vector_destroy(keys);
    dictionary_destroy(connections);
}


int main(int argc, char **argv) {
    // good luck!
    if (argc != 2) {
        print_server_usage();
        exit(1);
    }

    char template[] = "XXXXXX";
    dir_name = mkdtemp(template);
    if (!dir_name) {
        perror("create temp dir fail");
        return 1;
    }
    print_temp_directory(dir_name);

    files = shallow_vector_create();
    connections = shallow_to_shallow_dictionary_create();

    struct sigaction act;
    memset(&act, '\0', sizeof(act));
    act.sa_handler = close_server;
    if (sigaction(SIGINT, &act, NULL) < 0) {
        perror("sigaction failed");
        exit(1);
    }

    struct sigaction act2;
    memset(&act2, '\0', sizeof(act2));
    act2.sa_handler = sigpipe;
    if (sigaction(SIGPIPE, &act2, NULL) < 0) {
        perror("sigaction failed");
        exit(1);
    }

    run_server(argv[1]);
    clean_up();
}
