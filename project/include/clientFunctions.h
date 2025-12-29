// AUTO-REFACTORED: split header/implementation for modular build
#ifndef CLIENTFUNCTIONS_H
#define CLIENTFUNCTIONS_H

// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

#define BUFFER_SIZE 1024 // buffer size for the messages

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include "utils.h"

//this function handles the sending something to the server

int client_download(char *server_path, char *client_path, int client_socket);
int client_upload(char *client_path, int client_socket, char *loggedUser);
int client_read(int client_socket);
int client_write(int client_socket);

#endif // CLIENTFUNCTIONS_H
