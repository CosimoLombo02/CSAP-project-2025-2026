// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

#define BUFFER_SIZE 1024 // buffer size for the messages

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include "utils.h"

//this function handles the sending something  to the server
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

//this fuction handles the download of a file from the server
int client_download(char *server_path, char *client_path, int client_socket) {


    char buffer[BUFFER_SIZE];
    char final_path[PATH_MAX];
    struct stat st;

    // Determine if client_path is a directory
    if (stat(client_path, &st) == 0 && S_ISDIR(st.st_mode)) {
        snprintf(final_path, sizeof(final_path), "%s/%s", client_path, basename(server_path));
    } else {
        strncpy(final_path, client_path, sizeof(final_path) - 1);
        final_path[sizeof(final_path) - 1] = '\0';
    }

    // Wait for READY code (consumed by caller)
    // Server expects "OK"
    
    // Create local file
    int fd = open(final_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open client file");
        return -1;
    }
    
    if (send(client_socket, "OK\n", 3, 0) < 0) {
        perror("send OK");
        close(fd);
        return -1;
    }

    // Receive size
    uint64_t net_size;
    if (recv(client_socket, &net_size, sizeof(net_size), MSG_WAITALL) != sizeof(net_size)) {
        perror("recv size");
        close(fd);
        return -1;
    }
    uint64_t file_size = be64toh(net_size);

    // Receive content
    uint64_t bytes_received = 0;
    while (bytes_received < file_size) {
        size_t to_read = BUFFER_SIZE;
        if (to_read > (size_t)(file_size - bytes_received)) to_read = (size_t)(file_size - bytes_received);

        ssize_t n = recv(client_socket, buffer, to_read, 0);
        if (n <= 0) {
            perror("recv file");
            close(fd);
            return -1;
        }

        if (write(fd, buffer, n) != n) {
            perror("write file");
            close(fd);
            return -1;
        }
        bytes_received += (uint64_t)n;
    }

    close(fd);
    return 0;
}//end client_download

//this function handles the upload of a file to the server
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
}//end client_upload

//this function handles the read command client side
int client_read(int client_socket) {
    
    // Send OK to server to start receiving
    if (send(client_socket, "OK\n", 3, 0) < 0) {
        perror("send OK");
        return -1;
    }

    // Receive size
    uint64_t net_size;
    if (recv(client_socket, &net_size, sizeof(net_size), MSG_WAITALL) != sizeof(net_size)) {
        perror("recv size");
        return -1;
    }
    uint64_t file_size = be64toh(net_size);

    // Receive content and print to stdout
    char buffer[BUFFER_SIZE];
    uint64_t bytes_received = 0;
    while (bytes_received < file_size) {
        size_t to_read = BUFFER_SIZE;
        if (to_read > (size_t)(file_size - bytes_received)) to_read = (size_t)(file_size - bytes_received);

        ssize_t n = recv(client_socket, buffer, to_read, 0);
        if (n <= 0) {
            perror("recv file");
            return -1;
        }

        if (write(STDOUT_FILENO, buffer, n) != n) {
            perror("write to stdout");
            return -1;
        }
        bytes_received += (uint64_t)n;
    }
    // ensure a newline at the end if not present? POSIX usually implies text files end with newline.
    // user requirement just says "print it in stdout". 
    // If the file content doesn't have a newline at end, the prompt might appear on same line. 
    // Ideally we print exactly what we get.
    
    return 0;
}//end client_read

//this function handles the write command client side
int client_write(int client_socket) {
    char temp_filename[] = "/tmp/csap_write_XXXXXX";
    int temp_fd = mkstemp(temp_filename);
    if (temp_fd == -1) {
        perror("mkstemp");
        return -1;
    }

    printf("Enter text. Press Ctrl+D to finish.\n");

    // Read from stdin and write to temp file
    char buf[BUFFER_SIZE];
    ssize_t n;
    while ((n = read(STDIN_FILENO, buf, BUFFER_SIZE)) > 0) {
        if (write(temp_fd, buf, n) != n) {
            perror("write temp");
            close(temp_fd);
            unlink(temp_filename);
            return -1;
        }
    }
    
    // Get file size
    struct stat st;
    if (fstat(temp_fd, &st) < 0) {
        perror("fstat");
        close(temp_fd);
        unlink(temp_filename);
        return -1;
    }
    
    // Rewind for reading
    if (lseek(temp_fd, 0, SEEK_SET) < 0) {
        perror("lseek");
        close(temp_fd);
        unlink(temp_filename);
        return -1;
    }

    // Send OK to handshake
    if (send(client_socket, "OK\n", 3, 0) < 0) {
        perror("send OK");
        close(temp_fd);
        unlink(temp_filename);
        return -1;
    }

    // Send Size
    uint64_t file_size = st.st_size;
    uint64_t net_size = htobe64(file_size);
    if (send_all(client_socket, &net_size, sizeof(net_size)) < 0) {
        perror("send size");
        close(temp_fd);
        unlink(temp_filename);
        return -1;
    }

    // Send Content
    while ((n = read(temp_fd, buf, sizeof(buf))) > 0) {
        if (send_all(client_socket, buf, n) < 0) {
            perror("send content");
            close(temp_fd);
            unlink(temp_filename);
            return -1;
        }
    }

    close(temp_fd);
    unlink(temp_filename);
    
    return 0;
}//end client_write