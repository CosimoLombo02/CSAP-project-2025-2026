// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

// AUTO-REFACTORED implementation from serverFunctions.h
#include "serverFunctions.h"
#include "lockServer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

char loggedUser[64] = "";
char loggedCwd[PATH_MAX] = "";

int create_system_user(char *username) {

  // char *group = get_group();
  gid_t group = original_gid;
  char gid_str[32];
  snprintf(gid_str, sizeof(gid_str), "%d", group);

  if (username == NULL || strlen(username) == 0) {
    perror("Invalid username");
    return 0;
  }

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork failed");
    return 0;
  }

  if (pid == 0) {
    seteuid(0); // up to root
                // child: execute the command
    execlp("sudo", "sudo", "adduser", "--disabled-password", "--gecos", "",
           username, "--gid", gid_str, (char *)NULL);

    // if I get here, exec failed
    seteuid(original_uid); // back to non-root
    perror("execlp failed");
    _exit(1);
  }

  // parent: wait for the child
  int status;
  if (waitpid(pid, &status, 0) < 0) {
    perror("waitpid failed");
    return 0;
  }

  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    // adduser terminated with exit code 0
    return 1;
  } else {
    fprintf(stderr, "adduser failed (status=%d)\n", status);
    return 0;
  }
} // end create user



// login function

char *login(char *username, int client_socket, char *loggedUser) {

  if (loggedUser[0] != '\0') {
    send_with_cwd(client_socket, "You are already logged in!\n", loggedUser); // send the message to the client
    return NULL;
  } // end if

  // check if the username is null or made only by spaces
  if (username == NULL || strlen(username) == 0) {
    send_with_cwd(client_socket, "Insert Username!\n", loggedUser); // send the message to the client
    return NULL;
  } // end if

  // up to root
    if (seteuid(0) == -1) {
      perror("seteuid(0) failed");
      return NULL;
    } // end if

  if (check_directory(username) == 1) {

    // impersonate the user
    if (seteuid(get_uid_by_username(username)) == -1) {
      perror("seteuid failed");
      return NULL;
    } // end if

    // if the user creates the directory without permission we return NULL and we notify the client with "Login failed!" 
    // without writing the real error
    if (change_directory(username) == 0) {
      perror("change_directory failed");

      // up to root
      if (seteuid(0) == -1) {
        perror("seteuid(0) failed");
        return NULL;
      } // end if

      // back to non-root
      if (seteuid(original_uid) == -1) {
        perror("seteuid(original_uid) failed");
        return NULL;
      } // end if

      send_with_cwd(client_socket, "Login failed!\n", loggedUser); // send the message to the client
      return NULL;
    } // end if

    // up to root
    if (seteuid(0) == -1) {
      perror("seteuid(0) failed");
      return NULL;
    } // end if

    // back to non-root
    if (seteuid(original_uid) == -1) {
      perror("seteuid(original_uid) failed");
      return NULL;
    } // end if

    write(client_socket, "Login successful!\n\n", strlen("Login successful!\n\n")); // just send text, no prompt yet

    strncpy(loggedCwd, getcwd(NULL, 0), sizeof(loggedCwd)-1);
    loggedCwd[sizeof(loggedCwd)-1] = '\0';

    // Check for pending requests
    if (shared_state) {
        sem_wait(&shared_state->mutex);
        for(int i=0; i<MAX_CLIENTS; i++) {
            if(shared_state->requests[i].valid && 
               shared_state->requests[i].status == 0 && 
               strcmp(shared_state->requests[i].receiver, username) == 0) {
                
                char msg[256];
                snprintf(msg, sizeof(msg), "Pending Request ID %d from %s: %s\n", 
                         shared_state->requests[i].id, 
                         shared_state->requests[i].sender, 
                         basename(shared_state->requests[i].filename));
                write(client_socket, msg, strlen(msg)); // Use write simply to avoid prompt spam
                shared_state->requests[i].notified = 1;
            }
        }
        sem_post(&shared_state->mutex);
    }
    
    // Send CWD prompt manually at the end
    send_with_cwd(client_socket, "", username);

    return username;

  } else {

    send_with_cwd(client_socket, "Login failed!\n", loggedUser); // send the message to the client

    // back to non-root
    if (seteuid(original_uid) == -1) {
      perror("seteuid(original_uid) failed");
      return NULL;

    } // end if

    return NULL;
  } // end else

  return NULL;

} // end login function

// this function creates a new user
void create_user(char *username, char *permissions, int client_sock) {

  if (username == NULL || strlen(username) == 0) {
    send_with_cwd(client_sock, "Insert Username!\n", loggedUser); // send the message to the client
    return;
  } // end if

  if (permissions == NULL || strlen(permissions) == 0) {
    send_with_cwd(client_sock, "Insert Permissions!\n", loggedUser); // send the message to the client
    return;
  } // end if


  // check if the permission are valid
  if (strlen(permissions) != 3) {
    send_with_cwd(client_sock,
          "Invalid Permissions (max 3 numbers and each number must be between "
          "0 and 7 )!\n",
          loggedUser); // send the message to the client
    return;
  } // end if

  if (check_permissions(permissions) == 0) {
    send_with_cwd(client_sock, "Invalid Permissions!\n", loggedUser); // send the message to the client
    return;
  } // end if

  // creation of the real user in the system
  if (create_system_user(username) == 0) {
    send_with_cwd(client_sock, "Error in the user creation!\n", loggedUser); // send the message to the client
    return;
  } // end if

  
  // up to root
  if (seteuid(0) == -1) {
    perror("seteuid(0) failed");
    return;
  } // end if

  char abs_path[PATH_MAX];

  build_abs_path(abs_path,original_cwd, username);

  //printf("DEBUG: abs_path: %s\n", abs_path);

  // create the user's home directory
  if (!create_directory(abs_path, strtol(permissions, NULL, 8))) {

    // if create_directory fails, we restore the original uid
    if (seteuid(original_uid) == -1) {
      perror("Error restoring effective UID");
      return;
    } // end if
    send_with_cwd(client_sock, "Error in the home directory creation!\n", loggedUser); // send the message to the client
    return;
  } // end if

  // changes the owner and group of the directory
  if (chown(abs_path, get_uid_by_username(username),original_gid) == -1) { 
    perror("chown failed");

    send_with_cwd(client_sock, "Error in the user creation!\n", loggedUser); // send the message to the client
    


    if (seteuid(original_uid) == -1) {
    perror("Error restoring effective UID");
    return;
  } // end if


    return;
  } // end if

  if (seteuid(original_uid) == -1) {
    perror("Error restoring effective UID");
    return;
  } // end if

  send_with_cwd(client_sock, "User created successfully!\n", loggedUser); // send the message to the client

  return;
} // end function create_user

// Helper to remove user from shared memory
void remove_logged_user(char *username) {
    if(!username || strlen(username) == 0 || !shared_state) return;

    sem_wait(&shared_state->mutex);
    for(int i=0; i<MAX_CLIENTS; i++) {
        if(shared_state->logged_users[i].valid && strcmp(shared_state->logged_users[i].username, username) == 0) {
            shared_state->logged_users[i].valid = 0;
            //printf("DEBUG: User %s logged out (removed from shared state)\n", username);
            break;
        }
    }
    sem_post(&shared_state->mutex);
}

// Function to handle transfer request with blocking wait
void handle_transfer_request(int client_sock, char *filename, char *dest_user) {
    if(!filename || strlen(filename)==0 || !dest_user || strlen(dest_user)==0) {
        send_with_cwd(client_sock, "Usage: transfer_request <file> <user>\n", loggedUser);
        return;
    }
    char source_path[PATH_MAX];

    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));
    build_abs_path(source_path, cwd, filename);
  
    if(seteuid(0) == -1) perror("seteuid 0");
    if(access(source_path, F_OK) == -1) {
        if(seteuid(original_uid) == -1) perror("seteuid restore");
        send_with_cwd(client_sock, "Source file does not exist!\n", loggedUser);
        return;
    }
    if(seteuid(original_uid) == -1) perror("seteuid restore");

    char dest_user_path[PATH_MAX];

    if (snprintf(dest_user_path, sizeof(dest_user_path),
             "%s/%s", root_directory, dest_user)
    >= (int)sizeof(dest_user_path)) {

    send_with_cwd(client_sock,
                  "Path too long\n",
                  loggedUser);
    return;
}

    //printf("DEBUG: Checking if %s exists\n", dest_user_path);
    
    build_abs_path(dest_user_path, original_cwd, dest_user);
    
    //printf("DEBUG: Destination user path: %s\n", dest_user_path);

    // up to root
    if(seteuid(0) == -1) perror("seteuid 0");
    if(check_directory(dest_user_path) == 0) {
        send_with_cwd(client_sock, "Destination user does not exist!\n", loggedUser);
        if(seteuid(original_uid) == -1) perror("seteuid restore");
        return;
    }
    if(seteuid(original_uid) == -1) perror("seteuid restore");
    
    // trace the transfer request on the server
    printf("Handling transfer_request for %s -> %s\n", filename, dest_user);

    // Block SIGUSR1 so we can wait for it safely with sigsuspend
    sigset_t mask, oldmask, waitmask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    sigprocmask(SIG_BLOCK, &mask, &oldmask);
    
    // Prepare waitmask (oldmask usually emptyset, but let's be safe: it should allow SIGUSR1)
    waitmask = oldmask;
    sigdelset(&waitmask, SIGUSR1);

    int found = 0;
    while(!found) {
        sem_wait(&shared_state->mutex);
        
        // Check if user is online
        for(int i=0; i<MAX_CLIENTS; i++) {
            if(shared_state->logged_users[i].valid && strcmp(shared_state->logged_users[i].username, dest_user) == 0) {
                found = 1;
                break;
            }
        } // end for

        if(found) {
             sem_post(&shared_state->mutex);
             break; 
        } // end if

        // Add myself to waiters
        int added = 0;
        int my_slot = -1;
        for(int i=0; i<MAX_CLIENTS; i++) {
            if(!shared_state->waiters[i].valid) {
                 shared_state->waiters[i].pid = getpid();
                 strncpy(shared_state->waiters[i].target_user, dest_user, 64);
                 shared_state->waiters[i].valid = 1;
                 my_slot = i;
                 added = 1;
                 break;
            } // end if
        } // end for
        sem_post(&shared_state->mutex);

        if(!added) {
            // Should not happen if MAX_CLIENTS is enough, but to avoid infinite loop
            send_with_cwd(client_sock, "Server busy (wait queue full)!\n", loggedUser);
            sigprocmask(SIG_SETMASK, &oldmask, NULL);
            return;
        }

        // Notify the server that we are waiting for the user to connect
        printf("User %s not online. Waiting (PID %d)...\n", dest_user, getpid());

        char wait_msg[256];
        snprintf(wait_msg, sizeof(wait_msg), "User %s not online. Waiting for connection...\n", dest_user);
        write(client_sock, wait_msg, strlen(wait_msg));

        sigsuspend(&waitmask); // Atomic release and wait

        //printf("DEBUG: Woke up!\n");
        
        // Cleanup waiter entry before looping or exiting
        sem_wait(&shared_state->mutex);
        if(my_slot != -1) shared_state->waiters[my_slot].valid = 0;
        sem_post(&shared_state->mutex);
    }
    
    // Restore signal mask
    sigprocmask(SIG_SETMASK, &oldmask, NULL);
  
    char resolved_source_path[PATH_MAX];
  
    // Impersonate user
    if (seteuid(0) == -1) { perror("seteuid 0"); return; }
    if (seteuid(get_uid_by_username(loggedUser)) == -1) { perror("seteuid user"); return; }

    if (realpath(source_path, resolved_source_path) == NULL) {
        perror("realpath");
        send_with_cwd(client_sock, "Error resolving source file path.\n", loggedUser);
        seteuid(0); seteuid(original_uid); // Restore original uid
        return;
    }
    
    // Restore original uid
    if (seteuid(0) == -1) { perror("seteuid 0"); return; }
    if (seteuid(original_uid) == -1) { perror("seteuid orig"); return; }

    if (strncmp(resolved_source_path, loggedCwd, strlen(loggedCwd)) != 0) {
        send_with_cwd(client_sock, "Error: Source file must be within your home directory.\n", loggedUser);
        return;
    }
    
    // Update source_path to resolved absolute path
    strncpy(source_path, resolved_source_path, PATH_MAX);
    
    sem_wait(&shared_state->mutex);
    
    // Find dest_user PID again
    pid_t dest_pid = -1;
    for(int i=0; i<MAX_CLIENTS; i++) {
        if(shared_state->logged_users[i].valid && strcmp(shared_state->logged_users[i].username, dest_user) == 0) {
            dest_pid = shared_state->logged_users[i].pid;
            break;
        }
    }
    
    if(dest_pid == -1) {
         sem_post(&shared_state->mutex);
         send_with_cwd(client_sock, "Error: User went offline unexpectedly.\n", loggedUser);
         return;
    }

    // Allocate Request
    int req_id = shared_state->request_counter++;
    int req_idx = -1;
    for(int i=0; i<MAX_CLIENTS; i++) {
        if(!shared_state->requests[i].valid) {
            req_idx = i;
            break; 
        }
    }

    if(req_idx == -1) {
        sem_post(&shared_state->mutex);
        send_with_cwd(client_sock, "Server busy (too many active requests).\n", loggedUser);
        return;
    }

    // Fill Request
    shared_state->requests[req_idx].id = req_id;
    strncpy(shared_state->requests[req_idx].sender, loggedUser, 64);
    shared_state->requests[req_idx].sender_pid = getpid();
    strncpy(shared_state->requests[req_idx].receiver, dest_user, 64);
    shared_state->requests[req_idx].receiver_pid = dest_pid;
    strncpy(shared_state->requests[req_idx].filename, source_path, PATH_MAX);
    shared_state->requests[req_idx].valid = 1;
    shared_state->requests[req_idx].status = 0; // Pending
    shared_state->requests[req_idx].notified = 0; // Not yet notified
    
    // impersonate the user
    if(seteuid(0) == -1) perror("seteuid 0");
    if(seteuid(get_uid_by_username(loggedUser)) == -1) perror("seteuid user");
    
    int fd = open(source_path, O_RDONLY);
    
    // Restore original uid
    if(seteuid(0) == -1) perror("seteuid 0");
    if(seteuid(original_uid) == -1) perror("seteuid orig");

    if(fd >= 0) {
      // Lock the file (Shared) and Track
        if(lock_shared_fd(fd) < 0) {
            close(fd);
            send_with_cwd(client_sock, "Error transferring file.\n", loggedUser);
            shared_state->requests[req_idx].valid = 0;
            sem_post(&shared_state->mutex);
            return;
        }
        track_transfer_lock(req_id, fd);
    } else {
        send_with_cwd(client_sock, "Error accessing file.\n", loggedUser);
        shared_state->requests[req_idx].valid = 0;
        sem_post(&shared_state->mutex);
        return;
    }

    sem_post(&shared_state->mutex);

    // Notify Receiver
    // We use SIGRTMIN for "New Request"
    kill(dest_pid, SIGRTMIN);

    char msg[256];
    snprintf(msg, sizeof(msg), "Request ID %d sent to %s. Waiting for accept/reject...\n", req_id, dest_user);
    send_with_cwd(client_sock, msg, loggedUser);

    return;
} // end send_file

// This function handles the reject request
void handle_reject(int client_sock, int req_id, char *loggedUser) {
    if(!shared_state) return;
    
    // Block SIGRTMIN to prevent deadlock if handler tries to access something (though we removed lock in handler, it's safer)
    sigset_t block_mask, old_mask;
    sigemptyset(&block_mask);
    sigaddset(&block_mask, SIGRTMIN);
    sigprocmask(SIG_BLOCK, &block_mask, &old_mask);
    
    sem_wait(&shared_state->mutex);
    int idx = -1;
    for(int i=0; i<MAX_CLIENTS; i++) {
        if(shared_state->requests[i].valid && shared_state->requests[i].id == req_id) {
             idx = i;
             break;
        }
    }
    
    if(idx == -1) {
        sem_post(&shared_state->mutex);
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        send_with_cwd(client_sock, "Request ID not found.\n", loggedUser);
        return;
    }
    
    // Check if I am the receiver
    if(strcmp(shared_state->requests[idx].receiver, loggedUser) != 0) {
        sem_post(&shared_state->mutex);
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        send_with_cwd(client_sock, "You are not the receiver of this request.\n", loggedUser);
        return;
    }
    
    // Notify Sender
    // We assume sender is blocked on SIGUSR2
    pid_t sender_pid = shared_state->requests[idx].sender_pid;
    kill(sender_pid, SIGUSR2);
    
    // UPDATE REQUEST STATUS
    shared_state->requests[idx].status = 2; // REJECTED
    
    sem_post(&shared_state->mutex);
    sigprocmask(SIG_SETMASK, &old_mask, NULL);
    
    char msg[128];
    snprintf(msg, sizeof(msg), "Transfer %d rejected.\n", req_id);
    send_with_cwd(client_sock, msg, loggedUser);
}

void handle_accept(int client_sock, char *dir, int req_id, char *loggedUser) {
    if(!shared_state) return;
    
    // Block SIGRTMIN
    sigset_t block_mask, old_mask;
    sigemptyset(&block_mask);
    sigaddset(&block_mask, SIGRTMIN);
    sigprocmask(SIG_BLOCK, &block_mask, &old_mask);
     
    sem_wait(&shared_state->mutex);
    int idx = -1;
    for(int i=0; i<MAX_CLIENTS; i++) {
        if(shared_state->requests[i].valid && shared_state->requests[i].id == req_id) {
             idx = i;
             break;
        }
    }
    
    if(idx == -1) {
        sem_post(&shared_state->mutex);
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        send_with_cwd(client_sock, "Request ID not found.\n", loggedUser);
        return;
    }
    
     // Check if I am the receiver
    if(strcmp(shared_state->requests[idx].receiver, loggedUser) != 0) {
        sem_post(&shared_state->mutex);
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        send_with_cwd(client_sock, "You are not the receiver of this request.\n", loggedUser);
        return;
    }
    
    char dest_path[PATH_MAX];
    char dest_dir_abs[PATH_MAX];
    
    // Copy request data
    char filename[PATH_MAX];
    strncpy(filename, shared_state->requests[idx].filename, PATH_MAX);
    pid_t sender_pid = shared_state->requests[idx].sender_pid;
    
    sem_post(&shared_state->mutex);
    sigprocmask(SIG_SETMASK, &old_mask, NULL); // Unblock signals during IO
    
    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));

    // Impersonate the user
    if (seteuid(0) == -1) { perror("seteuid 0"); return; }
    if (seteuid(get_uid_by_username(loggedUser)) == -1) { perror("seteuid user"); return; }

    if (!resolve_and_check_path(dir, loggedCwd, "accept")) {
         send_with_cwd(client_sock, "Invalid directory.\n", loggedUser);
         // Restore original uid
         if (seteuid(0) == -1) perror("seteuid 0");
         if (seteuid(original_uid) == -1) perror("seteuid orig");
         return;
    }

    // Restore original uid
    if (seteuid(0) == -1) { perror("seteuid 0"); return; }
    if (seteuid(original_uid) == -1) { perror("seteuid orig"); return; }

    build_abs_path(dest_dir_abs, cwd, dir);
    
    // Check if dir exists
    struct stat st;
    if(seteuid(0) == -1) perror("seteuid 0");
    if(seteuid(get_uid_by_username(loggedUser)) == -1) perror("seteuid user");
    if(stat(dest_dir_abs, &st) == -1 || !S_ISDIR(st.st_mode)) {
        send_with_cwd(client_sock, "Invalid directory.\n", loggedUser);

        // up to root
        if(seteuid(0) == -1) perror("seteuid 0");
        if(seteuid(original_uid) == -1) perror("seteuid orig");

        return;
    }

    // up to root
    if(seteuid(0) == -1) perror("seteuid 0");
    if(seteuid(original_uid) == -1) perror("seteuid orig");
    
    // Final path
    if (snprintf(dest_path, sizeof(dest_path),
             "%s/%s", dest_dir_abs, basename(filename))
    >= (int)sizeof(dest_path)) {

    send_with_cwd(client_sock,
                  "Path too long\n",
                  loggedUser);
    return;
}
    
    // up to root
    if(seteuid(0) == -1) { perror("seteuid 0"); return; }
    
    // Open source file with rb (read binary)
    FILE *src = fopen(filename, "rb");
    if(!src) {
        perror("fopen src");
        send_with_cwd(client_sock, "Error source file (permission/existence).\n", loggedUser);
        seteuid(original_uid);
        return;
    }
    
    // Open destination file with wb (write binary)
    FILE *dst = fopen(dest_path, "wb");
    if(!dst) {
        perror("fopen dst");
        fclose(src);
        send_with_cwd(client_sock, "Error dest file.\n", loggedUser);
        seteuid(original_uid);
        return;
    }
    
    char buf[4096];
    size_t n;
    while((n = fread(buf, 1, sizeof(buf), src)) > 0) fwrite(buf, 1, n, dst);
    
    fclose(src);
    fclose(dst);
    
    // CHOWN to receiver
    uid_t uid = get_uid_by_username(loggedUser);
    gid_t gid = get_gid_by_username(loggedUser);
    chown(dest_path, uid, gid);
    chmod(dest_path, 0700);
    
    // Restore original uid
    seteuid(original_uid);
    
    // NOTIFY SENDER (Wake up)
    kill(sender_pid, SIGUSR2);
    
    // UPDATE REQUEST STATUS
    sigprocmask(SIG_BLOCK, &block_mask, NULL); // Re-block for cleanup
    sem_wait(&shared_state->mutex);
    // Verify it is still there (idx matches)
    if(shared_state->requests[idx].id == req_id) {
        shared_state->requests[idx].status = 1; // ACCEPTED
    }
    sem_post(&shared_state->mutex);
    sigprocmask(SIG_SETMASK, &old_mask, NULL); // Unblock
    
    char msg[128];
    snprintf(msg, sizeof(msg), "Transfer %d accepted and completed.\n", req_id);
    send_with_cwd(client_sock, msg, loggedUser);
} // end handle accept

// This function checks if the client wants to exit
int handle_exit(char *buffer) {

  if (strcmp(buffer, "exit\n") == 0) {
    return 1;
  } // end if
  return 0;
} // end handle exit
