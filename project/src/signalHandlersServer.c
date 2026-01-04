// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

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
#include "signalHandlersServer.h"
#include "lockServer.h"

extern SharedState *shared_state;
extern char loggedCwd[PATH_MAX];
extern char start_cwd[PATH_MAX];

// Signal handler for SIGUSR1 (just to interrupt sigsuspend for initial wait)
void sigusr1_handler(int signo) { }

// Signal for SIGUSR2 (Wake up sender after resolution)
// Signal for SIGUSR2 (Wake up sender after resolution)
void sigusr2_handler(int signo) {
    if(!shared_state || current_client_sock == -1) return;
    
    pid_t my_pid = getpid();
    for(int i=0; i<MAX_CLIENTS; i++) {
        // Check for requests where I am the sender, valid is true, and status is set (1=Accepted, 2=Rejected)
        // We access shared memory optimistically without locks (signal handler context)
        if(shared_state->requests[i].valid && 
           shared_state->requests[i].sender_pid == my_pid &&
           shared_state->requests[i].status != 0) {
           
            int status = shared_state->requests[i].status;
            
            // Release the lock locally
            release_transfer_lock(shared_state->requests[i].id);

            // Mark request as handled (cleanup)
            // Invalidating it effectively removes it from the list
            shared_state->requests[i].valid = 0;
            
            char msg[1024];
            char *txt = (status == 1) ? "accepted" : "rejected";
            
            // Replicate CWD prompt logic for user convenience (as requested)
            char *display_cwd = loggedCwd;
            char *pos = strstr(loggedCwd, start_cwd);
            if (pos == loggedCwd) { 
                display_cwd = loggedCwd + strlen(start_cwd);
            }

            // Construct notification: Message + Newline + Newline + Prompt
            int len = snprintf(msg, sizeof(msg), "\nTransfer %d %s!\n\n%s > ", shared_state->requests[i].id, txt, display_cwd);
            write(current_client_sock, msg, len);
        }
    }
}

// Signal for SIGRTMIN (Notify receiver of new request)
/* NOTE: We can't access client_socket easily here to write() unless we make it global or passed in data.
   However, we are in the main server loop or child process.
   In the child process (handle_client), distinct signals can interrupt blocking calls?
   Actually, `handle_client` logic is synchronous. We need a way to notify the client ASYNC.
   Writing to the socket from a signal handler is risky but common for simple notifications if careful.
   Better approach: Set a flag and check it in the loop? 
   But the loop is blocked on `read`.
   If we write to the socket, it will appear as output to the client.
*/

// We need a global variable for the current client socket in the child process to write to it.
int current_client_sock = -1;

void sigrtmin_handler(int signo) {
    if(!shared_state || current_client_sock == -1) return;
    
    // Check for my requests
    // WARNING: We are in a signal handler. sem_wait is safe in theory but prone to deadlock if interrupted thread holds it.
    // We REMOVE locking here. We read shared memory optimistically.
    
    pid_t my_pid = getpid();
    for(int i=0; i<MAX_CLIENTS; i++) {
        // Simple read of valid and receiver_pid. If we see a partial write, it's unlikely to match both our PID and valid=1.
        if(shared_state->requests[i].valid && 
           shared_state->requests[i].receiver_pid == my_pid &&
           !shared_state->requests[i].notified) {
               
            shared_state->requests[i].notified = 1;
               
            // Find filename manually to avoid non-async-safe basename()
            // Increase buffer size to handle CWD
            char msg[1024];
            char *fname = shared_state->requests[i].filename;
            char *p = strrchr(fname, '/');
            if (p) fname = p + 1;

            char *display_cwd = loggedCwd;
            // Mimic send_with_cwd: strip start_cwd if present
            char *pos = strstr(loggedCwd, start_cwd);
            if (pos == loggedCwd) { 
                // Matches at start
                display_cwd = loggedCwd + strlen(start_cwd);
            }
            
            // If display_cwd is empty (root), make it "/"? 
            // Or send_with_cwd behavior: if path is relative, it just prints it.
            // If display_cwd is empty string, it prints " > " ?
            // Let's assume valid relative path if not root.
    
            int len = snprintf(msg, sizeof(msg), "\n[!] Incoming Transfer Request (ID: %d) from %s for file %s\nAccept with: accept <dir> %d\nReject with: reject %d\n\n%s > ", 
                     shared_state->requests[i].id, 
                     shared_state->requests[i].sender, 
                     fname,
                     shared_state->requests[i].id,
                     shared_state->requests[i].id,
                     display_cwd);
            
            write(current_client_sock, msg, len);
        }
    }
}

// Ignores the SIGCHLD signal to avoid zombies
void sigchld_handler(int s) {
  while (waitpid(-1, NULL, WNOHANG) > 0)
    ;
} // end function sigchld_handler