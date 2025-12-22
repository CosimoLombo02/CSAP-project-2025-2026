// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

#define BUFFER_SIZE 1024 // buffer size for the messages

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include "utils.h"

static int send_all(int s, const void *buf, size_t len) {
    const char *p = buf;
    while (len > 0) {
        ssize_t w = send(s, p, len, 0);
        if (w <= 0) return -1;
        p += w;
        len -= (size_t)w;
    }
    return 0;
}

int client_upload(char *client_path, int client_socket, char *loggedUser) {
    
    char *full_path = malloc(strlen(client_path) + strlen(getcwd(NULL, 0)) + 2);
    if (full_path == NULL) {
        perror("malloc");
        return -1;
    }

    snprintf(full_path, strlen(client_path) + strlen(getcwd(NULL, 0)) + 2, "%s/%s", getcwd(NULL, 0), client_path);

    


    int fd = open(full_path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }


    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return -1; }

    uint64_t file_size = st.st_size;
    uint64_t net_size = htobe64(file_size);

    if (send_all(client_socket, &net_size, sizeof(net_size)) < 0) {
        perror("send size"); close(fd); return -1;
    }

    char buffer[BUFFER_SIZE];
    ssize_t n;

    while ((n = read(fd, buffer, BUFFER_SIZE)) > 0) {
        if (send_all(client_socket, buffer, n) < 0) {
            perror("send"); close(fd); return -1;
        }
    }
    close(fd);

return 0;
}