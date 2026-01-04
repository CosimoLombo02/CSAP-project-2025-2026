#include "lockServer.h"
#include "serverFunctions.h" 
#include "utils.h" /* for unlock_fd likely */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

// Lock Tracking
typedef struct {
    int req_id;
    int fd;
} TransferLock;

static TransferLock held_locks[MAX_CLIENTS];

// Initialize locks
static void init_locks() {
    static int initialized = 0;
    if(!initialized) {
        for(int i=0; i<MAX_CLIENTS; i++) held_locks[i].fd = -1;
        initialized = 1;
    }
}

void track_transfer_lock(int req_id, int fd) {
    init_locks();
    for(int i=0; i<MAX_CLIENTS; i++) {
        if(held_locks[i].fd == -1) {
            held_locks[i].req_id = req_id;
            held_locks[i].fd = fd;
            return;
        }
    }
}

void release_transfer_lock(int req_id) {
    init_locks();
    for(int i=0; i<MAX_CLIENTS; i++) {
        if(held_locks[i].fd != -1 && held_locks[i].req_id == req_id) {
            unlock_fd(held_locks[i].fd);
            close(held_locks[i].fd);
            held_locks[i].fd = -1;
            return;
        }
    }
}

// Check if file is locked by a pending transfer
int is_file_locked_by_transfer(char *path) {
    struct stat target_st;
    if(stat(path, &target_st) < 0) return 0;

    init_locks();
    for(int i=0; i<MAX_CLIENTS; i++) {
        if(held_locks[i].fd != -1) {
            struct stat lock_st;
            if(fstat(held_locks[i].fd, &lock_st) == 0) {
                if(target_st.st_dev == lock_st.st_dev && target_st.st_ino == lock_st.st_ino) {
                    return 1;
                }
            }
        }
    }
    return 0;
}
