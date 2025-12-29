// AUTO-REFACTORED: split header/implementation for modular build
#ifndef SERVERFUNCTIONS_H
#define SERVERFUNCTIONS_H

// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

#define BUFFER_SIZE 1024 // buffer size for the messages

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <libgen.h>
#include "fileSystem.h"
#include "utils.h"
#include <semaphore.h>
#include <signal.h>
#include <sys/mman.h>

#define MAX_CLIENTS 50

// Structure to track waiting processes
typedef struct {
    pid_t pid;
    char target_user[64];
    int valid; // 1 = waiting, 0 = empty
} WaitingProcess;

// Shared Memory Structure
typedef struct {
    char username[64];
    pid_t pid; // Process ID handling this user
    int valid; // 0 = empty, 1 = occupied
} LoggedUser;

typedef struct {
    int id;
    char sender[64];
    pid_t sender_pid;
    char receiver[64];
    pid_t receiver_pid;
    char filename[PATH_MAX]; // Absolute path
    int valid;
    int status; // 0=Pending, 1=Accepted, 2=Rejected
} TransferRequest;

typedef struct {
    LoggedUser logged_users[MAX_CLIENTS];
    WaitingProcess waiters[MAX_CLIENTS];
    TransferRequest requests[MAX_CLIENTS];
    int request_counter;
    sem_t mutex; // Semaphore for mutual exclusion
} SharedState;

// Global pointer to shared memory (must be initialized in main/server.c)
extern SharedState *shared_state;
extern int current_client_sock;

// Global variables
extern uid_t original_uid;
extern gid_t original_gid;
extern char original_cwd[PATH_MAX]; 
extern char root_directory[PATH_MAX];
extern char loggedUser[64];
extern char loggedCwd[PATH_MAX];

// create a real user in the system

int create_system_user(char *username);
char *login(char *username, int client_socket, char *loggedUser);
void create_user(char *username, char *permissions, int client_sock);
void remove_logged_user(char *username);
void handle_transfer_request(int client_sock, char *filename, char *dest_user);
void handle_reject(int client_sock, int req_id, char *loggedUser);
void handle_accept(int client_sock, char *dir, int req_id, char *loggedUser);
void handle_client(int client_sock);
void sigchld_handler(int s);
int handle_exit(char *buffer);

#endif // SERVERFUNCTIONS_H
