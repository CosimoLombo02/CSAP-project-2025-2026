// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

// AUTO-REFACTORED: split header/implementation for modular build
#ifndef UPLOAD_DOWNLOAD_CLIENT_H
#define UPLOAD_DOWNLOAD_CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 1024
#endif

// Logged user (client-side)
extern char logged_user[64];

// Struct for active operations
typedef enum { OP_UPLOAD, OP_DOWNLOAD } OperationType;

// Struct for active operations
typedef struct ActiveOperation {
    pid_t pid;
    OperationType type;
    char server_path[PATH_MAX];
    char client_path[PATH_MAX];
    struct ActiveOperation *next;
} ActiveOperation;

// Global variables
extern ActiveOperation *active_operations;
extern char current_prompt[BUFFER_SIZE];

// Here there are the declarations of the functions that are in uploadDownloadClient.c
void update_prompt(const char *buffer);
void add_operation(pid_t pid, OperationType type, char *server_path, char *client_path);
void remove_and_print_operation(pid_t pid, int status);
void sigchld_handler(int sig);

#endif // UPLOAD_DOWNLOAD_CLIENT_H
