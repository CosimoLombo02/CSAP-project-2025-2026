// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

#ifndef SIGNALHANDLERS_SERVER_H
#define SIGNALHANDLERS_SERVER_H

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "serverFunctions.h"


void sigusr1_handler(int signo);
void sigusr2_handler(int signo);
void sigrtmin_handler(int signo);
void sigchld_handler(int s);

#endif // SIGNALHANDLERS_SERVER_H

