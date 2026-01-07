// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

// AUTO-REFACTORED: split header/implementation for modular build
#ifndef LOCKSERVER_H
#define LOCKSERVER_H

// Here there are the declarations of the functions that are in lockServer.c
void track_transfer_lock(int req_id, int fd);
void release_transfer_lock(int req_id);
int is_file_locked_by_transfer(char *path);

#endif // LOCKSERVER_H
