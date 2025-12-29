// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

// AUTO-REFACTORED: split header/implementation for modular build
#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 1024
#endif

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include <pwd.h> 
#include <grp.h> 
#include <sys/file.h> 

extern char start_cwd[PATH_MAX];

// lock the file with shared lock

int lock_shared_fd(int fd);
int lock_exclusive_fd(int fd);
int unlock_fd(int fd);
int create_directory(char *directory, mode_t permissions);
int create_file(char *file, mode_t permissions);
int change_directory(char * path);
void send_with_cwd(int client_sock, const char *msg, char *loggedUser);
void format_permissions(mode_t mode, char *perms);
void file_info_string(const char *fullpath, char *out, size_t out_size);
void list_directory_string(const char *path, char *out, size_t out_size);
void handle_upload(int client_sock, char *server_path, char* client_path, char *loggedUser, uid_t uid, gid_t gid);
void handle_download(int client_sock, char *server_path, char *loggedUser);
int handle_chmod(char *server_path, char *permissions);
int handle_mv(const char *old_abs, const char *new_abs);
int handle_delete(char *server_path);
void handle_read(int client_sock, char *server_path, char *loggedUser, long offset);
void handle_write(int client_sock, char *server_path, char *loggedUser, long offset);

#endif // FILESYSTEM_H
