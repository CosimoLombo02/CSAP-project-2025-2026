// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

#define BUFFER_SIZE 1024 // buffer size for the messages

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>

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

void client_upload(char *client_path, int client_socket) {

    printf("Client path: %s\n", client_path);
    printf("Logged CWD: %s\n", getcwd(NULL, 0));

    int fd = open(client_path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return;
    }

    char response[16];
    recv(client_socket, response, sizeof(response), 0);

    struct stat st;
    fstat(fd, &st);

    uint64_t file_size = st.st_size;
    uint64_t net_size = htobe64(file_size);

    send_all(client_socket, &net_size, sizeof(net_size));

    char buffer[BUFFER_SIZE];
    ssize_t n;

    while ((n = read(fd, buffer, BUFFER_SIZE)) > 0) {
        fwrite(buffer, 1, n, stdout);
        send_all(client_socket, buffer, n);
    }
    close(fd);

    recv(client_socket, response, sizeof(response), 0);
    printf("Server: %s\n", response); // just for debugging

    



    

}