#ifndef LOCKSERVER_H
#define LOCKSERVER_H

// Tracks a file descriptor locked for a specific transfer request
void track_transfer_lock(int req_id, int fd);

// Releases the lock associated with a transfer request
void release_transfer_lock(int req_id);

// Checks if a file is currently locked by any pending transfer
int is_file_locked_by_transfer(char *path);

#endif // LOCKSERVER_H
