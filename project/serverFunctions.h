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
char loggedUser[64] = "";
char loggedCwd[PATH_MAX] = "";

// create a real user in the system
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

    change_directory(username);

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

    send_with_cwd(client_socket, "Login successful!\n", username); // send the message to the client

    strncpy(loggedCwd, getcwd(NULL, 0), sizeof(loggedCwd)-1);
    loggedCwd[sizeof(loggedCwd)-1] = '\0';

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

  printf("DEBUG: abs_path: %s\n", abs_path); //debug

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

  chown(username, get_uid_by_username(username),
        original_gid); // changes the owner and group of the directory

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
            printf("DEBUG: User %s logged out (removed from shared state)\n", username);
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

    // Check if source file exists FIRST
    char source_path[PATH_MAX];

    if (snprintf(source_path, sizeof(source_path),
             "%s/%s", loggedCwd, filename)
    >= sizeof(source_path)) {

    send_with_cwd(client_sock,
                  "Path too long\n",
                  loggedUser);
    return;
}

    // We need to check if we can read it.
    // Ideally use access() but we are running as root or original_uid?
    // We are running as root (seteuid(0) was called in main? No, seteuid(original_uid)).
    // So we need to seteuid(0) to check file owned by user?
    // The server runs effectively as root eventually?
    // Using `access` might check real UID/GID.
    // Better: elevate to 0, check, restore.
    
    if(seteuid(0) == -1) perror("seteuid 0");
    if(access(source_path, F_OK) == -1) {
        if(seteuid(original_uid) == -1) perror("seteuid restore");
        send_with_cwd(client_sock, "Source file does not exist!\n", loggedUser);
        return;
    }
    if(seteuid(original_uid) == -1) perror("seteuid restore");

    // Check if dest_user home directory exists in the root directory
    char dest_user_path[PATH_MAX];

    if (snprintf(dest_user_path, sizeof(dest_user_path),
             "%s/%s", root_directory, dest_user)
    >= sizeof(dest_user_path)) {

    send_with_cwd(client_sock,
                  "Path too long\n",
                  loggedUser);
    return;
}

    printf("DEBUG: Checking if %s exists\n", dest_user_path);
    
    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));
    build_abs_path(dest_user_path, original_cwd, dest_user);

    //debug
    
    printf("DEBUG: Destination user path: %s\n", dest_user_path);


    if(check_directory(dest_user_path) == 0) {
        send_with_cwd(client_sock, "Destination user does not exist!\n", loggedUser);
        return;
    }
    

    printf("DEBUG: Handling transfer_request for %s -> %s\n", filename, dest_user);

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
        }

        if(found) {
             sem_post(&shared_state->mutex);
             break; 
        }

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
            }
        }
        sem_post(&shared_state->mutex);

        if(!added) {
            // Should not happen if MAX_CLIENTS is enough, but to avoid infinite loop
            send_with_cwd(client_sock, "Server busy (wait queue full)!\n", loggedUser);
            sigprocmask(SIG_SETMASK, &oldmask, NULL);
            return;
        }

        printf("DEBUG: User %s not online. Waiting (PID %d)...\n", dest_user, getpid());

        // Notify client that we are waiting (this unblocks the client READ, but server remains blocked in handle_client)
        // The user will see the prompt but commands will hang until server wakes up.
        char wait_msg[256];
        snprintf(wait_msg, sizeof(wait_msg), "User %s not online. Waiting for connection...\n", dest_user);
        // send_with_cwd(client_sock, wait_msg, loggedUser);
        // USE write directly to avoid sending the prompt (CWD >), so the user knows we are waiting.
        write(client_sock, wait_msg, strlen(wait_msg));

        sigsuspend(&waitmask); // Atomic release and wait
        printf("DEBUG: Woke up!\n");
        
        // Cleanup waiter entry before looping or exiting
        sem_wait(&shared_state->mutex);
        if(my_slot != -1) shared_state->waiters[my_slot].valid = 0;
        sem_post(&shared_state->mutex);
    }
    
    // Restore signal mask
    sigprocmask(SIG_SETMASK, &oldmask, NULL);

    // --- Create Transfer Request ---
    // At this point, dest_user is online.
    
    // 1. Resolve Source Path (cwd/filename)
    // Validate that source_path is within the user's sandbox
    char resolved_source_path[PATH_MAX];
    if (realpath(source_path, resolved_source_path) == NULL) {
        send_with_cwd(client_sock, "Error resolving source file path.\n", loggedUser);
        return;
    }

    if (strncmp(resolved_source_path, loggedCwd, strlen(loggedCwd)) != 0) {
        send_with_cwd(client_sock, "Error: Source file must be within your home directory.\n", loggedUser);
        return;
    }
    
    // Update source_path to resolved absolute path
    strncpy(source_path, resolved_source_path, PATH_MAX);


    sem_wait(&shared_state->mutex);
    
    // Find dest_user PID again (it might have changed if they relogged, though we just passed blocking)
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

    sem_post(&shared_state->mutex);

    // Notify Receiver
    // We use SIGRTMIN for "New Request"
    kill(dest_pid, SIGRTMIN);

    char msg[256];
    snprintf(msg, sizeof(msg), "Request ID %d sent to %s. Waiting for accept/reject...\n", req_id, dest_user);
    send_with_cwd(client_sock, msg, loggedUser);
    
    // NON-BLOCKING for the Sender (as requested)
    // We return immediately. 
    // The Sender process will continue handling its client.
    // When the Receiver eventually Accepts/Rejects, it will send SIGUSR2 to THIS process (Sender PID).
    // The SIGUSR2 handler in server.c must handle the notification to the client.

    return;
}


/*This function is a the main function that handles the client,
as we can see it has different behaviuors based on the message received  */
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
    
    send_with_cwd(client_sock, "Request rejected.\n", loggedUser);
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
    
    // Perform Transfer
    // 1. Resolve Dest Path
    char dest_path[PATH_MAX];
    char dest_dir_abs[PATH_MAX];
    
    // Resolve 'dir' relative to CWD
    
    // Copy request data
    char filename[PATH_MAX];
    strncpy(filename, shared_state->requests[idx].filename, PATH_MAX);
    pid_t sender_pid = shared_state->requests[idx].sender_pid;
    
    sem_post(&shared_state->mutex);
    sigprocmask(SIG_SETMASK, &old_mask, NULL); // Unblock signals during IO
    
    // RESOLVE PATHS
    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));
    build_abs_path(dest_dir_abs, cwd, dir);
    
    // Check if dir exists
    struct stat st;
    if(stat(dest_dir_abs, &st) == -1 || !S_ISDIR(st.st_mode)) {
        send_with_cwd(client_sock, "Invalid directory.\n", loggedUser);
        return;
    }
    
    // Final path
    if (snprintf(dest_path, sizeof(dest_path),
             "%s/%s", dest_dir_abs, basename(filename))
    >= sizeof(dest_path)) {

    send_with_cwd(client_sock,
                  "Path too long\n",
                  loggedUser);
    return;
}
    
    // ELEVATE TO ROOT for reading source (owned by sender) and writing dest (owned by receiver)
    if(seteuid(0) == -1) { perror("seteuid 0"); return; }
    
    FILE *src = fopen(filename, "rb");
    if(!src) {
        perror("fopen src");
        send_with_cwd(client_sock, "Error source file (permission/existence).\n", loggedUser);
        seteuid(original_uid);
        return;
    }
    
    FILE *dst = fopen(dest_path, "wb");
    if(!dst) {
        perror("fopen dst");
        fclose(src);
        send_with_cwd(client_sock, "Error dest file.\n", loggedUser);
        seteuid(original_uid);
        return;
    }
    
    // COPY
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
    
    // RESTORE
    seteuid(original_uid);
    
    // NOTIFY SENDER (Wake up)
    kill(sender_pid, SIGUSR2);
    
    // UPDATE REQUEST STATUS
    sigprocmask(SIG_BLOCK, &block_mask, NULL); // Re-block for cleanup
    sem_wait(&shared_state->mutex);
    // Verify it is still there (idx matches) - simplistic
    if(shared_state->requests[idx].id == req_id) {
        shared_state->requests[idx].status = 1; // ACCEPTED
    }
    sem_post(&shared_state->mutex);
    sigprocmask(SIG_SETMASK, &old_mask, NULL); // Unblock
    
    send_with_cwd(client_sock, "Transfer accepted and completed.\n", loggedUser);
}


/*This function is a the main function that handles the client,
as we can see it has different behaviuors based on the message received  */
void handle_client(int client_sock) {

  // Set global for signal handler
  current_client_sock = client_sock;

  // Reset SIGCHLD to default so we can waitpid() on our own children (e.g. adduser)
  signal(SIGCHLD, SIG_DFL);

  char buffer[BUFFER_SIZE];
  char cwd[PATH_MAX];
  int n;

  

  while (1) {
    n = read(client_sock, buffer, BUFFER_SIZE - 1);
    
    if (n < 0) {
        if (errno == EINTR) continue; // Ignore signal interruptions
        perror("read error");
        break;
    } 
    if (n == 0) {
        break; // Client disconnected
    }
   
    buffer[n] = '\0'; /*Terminates the buffer, maybe we can consider this as a
    buffer overflow security measure ?
    */
    printf("Client: %s",
           buffer); // print the message received from the client, server side
    // write(client_sock, buffer, n); //send the message to the client

    printf("DEBUG start-while euid: %d\n", geteuid()); // debug

    // test
    char *firstToken = strtok(buffer, " "); // first token is the command
    char *secondToken = strtok(NULL, " ");  // second token of the command
    char *thirdToken = strtok(NULL, " ");   // third token of the command
    char *fourthToken = strtok(NULL, " ");  // fourth token of the command
   

    // removes eventually \n
    if (firstToken != NULL) {
      firstToken[strcspn(firstToken, "\n")] = '\0';
    }
    if (secondToken != NULL) {
      secondToken[strcspn(secondToken, "\n")] = '\0';
    }
    if (thirdToken != NULL) {
      thirdToken[strcspn(thirdToken, "\n")] = '\0';
    }
    if (fourthToken != NULL) {
      fourthToken[strcspn(fourthToken, "\n")] = '\0';
    }


    if (strcmp("login", firstToken) == 0) {

      char *tmp = login(secondToken, client_sock, loggedUser);

      // if the login is successful we store the username in the loggedUser variable
      if(tmp!=NULL){
        strncpy(loggedUser, tmp, sizeof(loggedUser)-1);
        loggedUser[sizeof(loggedUser)-1] = '\0';
        
        // Add to Shared Memory
        if(shared_state) {
            sem_wait(&shared_state->mutex);
            for(int i=0; i<MAX_CLIENTS; i++) {
                if(!shared_state->logged_users[i].valid) {
                    strncpy(shared_state->logged_users[i].username, loggedUser, 64);
                    shared_state->logged_users[i].pid = getpid(); // Store PID
                    shared_state->logged_users[i].valid = 1;
                    break;
                }
            }
            
            // Wake up waiting processes
            for(int i=0; i<MAX_CLIENTS; i++) {
                if(shared_state->waiters[i].valid && strcmp(shared_state->waiters[i].target_user, loggedUser) == 0) {
                    printf("DEBUG: Waking up PID %d waiting for %s\n", shared_state->waiters[i].pid, loggedUser);
                    kill(shared_state->waiters[i].pid, SIGUSR1);
                }
            }
            sem_post(&shared_state->mutex);
            
            // Check for pending requests for me?
            // (Optional: Could iterate requests and notify myself, but usually notification happens at creation time or poll)
        }
      }

    } else if (strcmp("create_user", firstToken) == 0) {

        // call the function for creating the user
        create_user(secondToken, thirdToken, client_sock);

    } else if (strcmp("create", firstToken) == 0) {

      if (loggedUser[0] == '\0') { // if the user is not logged in
        send_with_cwd(client_sock, "You are not logged in!\n", loggedUser);
    } else {
      if (secondToken == NULL || strlen(secondToken) == 0) {
        send_with_cwd(client_sock, "Insert path!\n", loggedUser);
      } else {
       if (thirdToken == NULL || strlen(thirdToken) == 0) {
        send_with_cwd(client_sock, "Insert permissions!\n", loggedUser);
       } else {
        if (check_permissions(thirdToken) == 0) {
        send_with_cwd(client_sock, "Insert valid permissions!\n", loggedUser);
        } else {
          
          if(fourthToken!=NULL && strlen(fourthToken)!=0 && strcmp("-d",fourthToken)==0){

            // up to root
            if (seteuid(0) == -1) {
              perror("seteuid(0) failed");
              return;
            } // end if seteuid
            
            // set the uid of the user
            if (seteuid(get_uid_by_username(loggedUser)) == -1) {
              perror("seteuid(user) failed");
              return;
            } // end if seteuid

            if( resolve_and_check_path(secondToken, loggedCwd, "create")==1 && create_directory(secondToken,strtol(thirdToken, NULL, 8))==1){
              send_with_cwd(client_sock, "Directory created successfully!\n", loggedUser);
            } else {
              send_with_cwd(client_sock, "Error in the directory creation!\n", loggedUser);
            }

            // up to root
            if (seteuid(0) == -1) {
              perror("seteuid(0) failed");
              return;
            } // end if seteuid

            // restore the original uid
            if (seteuid(original_uid) == -1) {
              perror("Error restoring effective UID");
              return;
            } // end if seteuid

          } else {

            // up to root
            if (seteuid(0) == -1) {
              perror("seteuid(0) failed");
              return;
            } // end if seteuid
            
            // set the uid of the user
            if (seteuid(get_uid_by_username(loggedUser)) == -1) {
              perror("seteuid(user) failed");
              return;
            } // end if seteuid
            
            if( resolve_and_check_path(secondToken, loggedCwd, "create")==1 && create_file(secondToken,strtol(thirdToken, NULL, 8))==1 ){
              send_with_cwd(client_sock, "File created successfully!\n", loggedUser);
            } else {
              send_with_cwd(client_sock, "Error in the file creation!\n", loggedUser);
            }

            // up to root
            if (seteuid(0) == -1) {
              perror("seteuid(0) failed");
              return;
            } // end if seteuid

            // restore the original uid
            if (seteuid(original_uid) == -1) {
              perror("Error restoring effective UID");
              return;
            } // end if seteuid

          } // end else fourthToken



        } // end else check_permissions

       } // end else thirdToken
        
      } // end else secondToken

      
    } // end main else loggedUser

  }else if(strcmp(firstToken,"cd")==0){
  
        if(loggedUser[0]=='\0'){
          send_with_cwd(client_sock, "You are not logged in!\n", loggedUser);
        }else{
          if(secondToken==NULL || strlen(secondToken)==0){
            send_with_cwd(client_sock, "Insert path!\n", loggedUser);
          }else{

            // up to root
            if (seteuid(0) == -1) {
              perror("seteuid(0) failed");
              return;
            } // end if seteuid

            // impersonate loggedUser
            if (seteuid(get_uid_by_username(loggedUser)) == -1) {
              perror("seteuid(user) failed");
              return;
            } // end if seteuid

            if(resolve_and_check_path(secondToken, loggedCwd, "cd")==1 && change_directory(secondToken)==1){

              send_with_cwd(client_sock, "Directory changed successfully!\n", loggedUser);
            }else{
              send_with_cwd(client_sock, "Error in the directory change!\n", loggedUser);
            }

            // up to root
            if (seteuid(0) == -1) {
              perror("seteuid(0) failed");
              return;
            } // end if seteuid

            // restore the original uid
            if (seteuid(original_uid) == -1) {
              perror("Error restoring effective UID");
              return;
            } // end if seteuid            
          }//end else secondToken

        }//end else loggedUser cd
    } else if (strcmp(firstToken,"list")==0){
      if(loggedUser[0]=='\0'){
        send_with_cwd(client_sock, "You are not logged in!\n", loggedUser);
      }else{//here we have to implement the sandbox check
        char out[8192];

        // up to root
        if (seteuid(0) == -1) {
          perror("seteuid(0) failed");
          return;
        } // end if seteuid

        // impersonate loggedUser
        if (seteuid(get_uid_by_username(loggedUser)) == -1) {
          perror("seteuid(user) failed");
          return;
        } // end if seteuid

          if(secondToken==NULL || strlen(secondToken)==0){
            
            list_directory_string(".", out, sizeof(out));
            send_with_cwd(client_sock, out, loggedUser);
          }else{
            if(resolve_and_check_path(secondToken, loggedCwd, "list")==1){
              list_directory_string(secondToken, out, sizeof(out));
              send_with_cwd(client_sock, out, loggedUser);
            }else{
              send_with_cwd(client_sock, "Error in the directory listing!\n", loggedUser);
            }//end else directory listing
          }//end else secondToken
         
          // up to root
        if (seteuid(0) == -1) {
          perror("seteuid(0) failed");
          return;
        } // end if seteuid

        // restore original uid
        if (seteuid(original_uid) == -1) {
          perror("Error restoring effective UID");
          return;
        } // end if seteuid
          
        }//end else logged user list

    }else if(strcmp(firstToken,"upload")==0){
      if(loggedUser[0]=='\0'){
        send_with_cwd(client_sock, "You are not logged in!\n", loggedUser);
      }else{
        if(secondToken==NULL || strlen(secondToken)==0){
          send_with_cwd(client_sock, "Insert client path!\n", loggedUser);
        }else{
          if(thirdToken==NULL || strlen(thirdToken)==0){
            send_with_cwd(client_sock, "Insert server path!\n", loggedUser);
          }else{
            if(fourthToken==NULL || strlen(fourthToken)==0){
              if(resolve_and_check_path(thirdToken, loggedCwd, "upload")==1){

              
               // up to root
              if (seteuid(0) == -1) {
                perror("seteuid(0) failed");
                return;
              } // end if seteuid
               handle_upload(client_sock, thirdToken, secondToken, loggedUser, get_uid_by_username(loggedUser), get_gid_by_username(loggedUser));
               // back to non-root
              if (seteuid(original_uid) == -1) {
                perror("seteuid(original_uid) failed");
                return;
              } // end if seteuid
              
              }else{
                send_with_cwd(client_sock, "Error in the file upload!\n", loggedUser);
              }
              
            }//end if non existence of fouth token
            //for the background upload, the client makes a new fork and in the
            //child process calls the handle_upload function without the -b option
            
          }//end else thirdToken
          
        }//end else secondToken
      }//end else loggedUser upload
    }else if(strcmp(firstToken,"download")==0){
        if(loggedUser[0]=='\0'){
            send_with_cwd(client_sock, "You are not logged in!\n", loggedUser);
        } else {
            if(secondToken==NULL || strlen(secondToken)==0){
                send_with_cwd(client_sock, "Insert server path!\n", loggedUser);
            } else {
              if(thirdToken==NULL || strlen(thirdToken)==0){
                send_with_cwd(client_sock, "Insert local path!\n", loggedUser);
              }else{
                if(resolve_and_check_path(secondToken, loggedCwd, "download")==1){

                  // up to root
              if (seteuid(0) == -1) {
                perror("seteuid(0) failed");
                return;
              } // end if seteuid

              // set the uid of the user
              if (seteuid(get_uid_by_username(loggedUser)) == -1) {
                perror("seteuid(user) failed");
                return;
              } // end if seteuid

              handle_download(client_sock, secondToken, loggedUser);

              // up to root
              if (seteuid(0) == -1) {
                perror("seteuid(0) failed");
                return;
              } // end if seteuid

              // restore the original uid
              if (seteuid(original_uid) == -1) {
                perror("Error restoring effective UID");
                return;
                    } // end if seteuid
                }else{
                    send_with_cwd(client_sock, "Error in the file download!\n", loggedUser);
                }//end else resolve_and_check_path
            }//end else second token
          }//end else third token
        }//end else loggedUser download
      
    }else if(strcmp(firstToken,"chmod")==0){
      if(loggedUser[0]=='\0'){
        send_with_cwd(client_sock, "You are not logged in!\n", loggedUser);
      }else{
        if(secondToken==NULL || strlen(secondToken)==0){
          send_with_cwd(client_sock, "Insert file path!\n", loggedUser);
        }else{
          if(thirdToken==NULL || strlen(thirdToken)==0){
            send_with_cwd(client_sock, "Insert permissions!\n", loggedUser);
          }else{
            if(resolve_and_check_path(secondToken, loggedCwd, "chmod")==1){
              if(check_permissions(thirdToken)==0){
                  send_with_cwd(client_sock, "Invalid permissions!\n", loggedUser);
                
              }else{
                //if i am here i can change the permissions

                
               // up to root
              if (seteuid(0) == -1) {
                perror("seteuid(0) failed");
                return;
              }

              //set to loggedUser
              if (seteuid(get_uid_by_username(loggedUser)) == -1) {
                perror("seteuid(get_uid_by_username(loggedUser)) failed");
                return;
              }

                if(handle_chmod(secondToken, thirdToken)==-1){
                  send_with_cwd(client_sock, "Error in the file chmod!\n", loggedUser);
                }else{
                  send_with_cwd(client_sock, "File chmod successfully!\n", loggedUser);
                }
                
                // up to root
              if (seteuid(0) == -1) {
                perror("seteuid(0) failed");
                return;
              }
              

              //back to non-root
              if (seteuid(original_uid) == -1) {
                perror("seteuid(original_uid) failed");
                return;
              }
                
              
              }//end else checkpermissions
            }else{
              send_with_cwd(client_sock, "Error in the file chmod!\n", loggedUser);
            }//end else resolve_and_check_path
          }//end else third token
        }//end else second token
      }//end else loggedUser chmod 
        
      }else if(strcmp(firstToken,"move")==0){
        if(loggedUser[0]=='\0'){
          send_with_cwd(client_sock, "You are not logged in!\n", loggedUser);
        }else{
          if(secondToken==NULL || strlen(secondToken)==0){
            send_with_cwd(client_sock, "Insert old path!", loggedUser);
          }else{
            if(thirdToken==NULL || strlen(thirdToken)==0){
              send_with_cwd(client_sock, "Insert new path!", loggedUser);
            }else{
              if(resolve_and_check_path(secondToken, loggedCwd, "move")==1){
                if(resolve_and_check_path(thirdToken, loggedCwd, "move")==1){
                  
                  // up to root
                  if (seteuid(0) == -1) {
                    perror("seteuid(0) failed");
                    return;
                  }

                  // impersonate loggedUser
                  if (seteuid(get_uid_by_username(loggedUser)) == -1) {
                    perror("seteuid(user) failed");
                    return;
                  }

                  char old_abs[PATH_MAX];
                  char new_abs[PATH_MAX];
                  
                  getcwd(cwd, sizeof(cwd));

                  // build absolute paths
                  build_abs_path(old_abs, cwd, secondToken);
                  build_abs_path(new_abs, cwd, thirdToken);


                  if(handle_mv(old_abs, new_abs)==-1){
                    send_with_cwd(client_sock, "Error in the file mv!\n", loggedUser);
                  }else{
                    send_with_cwd(client_sock, "File moved successfully!\n", loggedUser);
                  }

                  // up to root
                  if (seteuid(0) == -1) {
                    perror("seteuid(0) failed");
                    return;
                  }

                  // restore original uid
                  if (seteuid(original_uid) == -1) {
                    perror("Error restoring effective UID");
                    return;
                  }

                }else{
                  send_with_cwd(client_sock, "Error in the file mv!\n", loggedUser);
                }
              }else{
                send_with_cwd(client_sock, "Error in the file mv!\n", loggedUser);
              }
            }//end else third token mv 
          }//end else second token mv 
        }//end else logged user mv
        
      }else if(strcmp(firstToken,"read")==0){
        if(loggedUser[0]=='\0'){
          send_with_cwd(client_sock, "You are not logged in!\n", loggedUser);
        }else{
            char *pathToken = secondToken;
            long offset = 0;
            
            if(secondToken && strncmp(secondToken, "-offset=", 8) == 0){
                offset = atol(secondToken + 8);
                pathToken = thirdToken;
            }
            
            if(pathToken == NULL || strlen(pathToken) == 0){
                 send_with_cwd(client_sock, "Insert path!\n", loggedUser);
            } else {
            // up to root
            if (seteuid(0) == -1) {
                perror("seteuid(0) failed");
                return;
            }
             // impersonate loggedUser
            if (seteuid(get_uid_by_username(loggedUser)) == -1) {
                perror("seteuid(user) failed");
                return;
            }

            if(resolve_and_check_path(pathToken, loggedCwd, "read")==1){
                    
                    char abs_path[PATH_MAX];
                    getcwd(cwd, sizeof(cwd));
                    build_abs_path(abs_path, cwd, pathToken);
                    
                    handle_read(client_sock, abs_path, loggedUser, offset);

                } else {
                    send_with_cwd(client_sock, "Error in the file read!\n", loggedUser);
                }

                // up to root
                if (seteuid(0) == -1) {
                    perror("seteuid(0) failed");
                    return;
                }
                // restore original uid
                if (seteuid(original_uid) == -1) {
                    perror("Error restoring effective UID");
                    return;
                }
            }
        }
        

        
      } else if(strcmp(firstToken,"write")==0){
        if(loggedUser[0]=='\0'){
          send_with_cwd(client_sock, "You are not logged in!\n", loggedUser);
        }else{
            char *pathToken = secondToken;
            long offset = 0;
            
            if(secondToken && strncmp(secondToken, "-offset=", 8) == 0){
                offset = atol(secondToken + 8);
                pathToken = thirdToken;
            }
            
            if(pathToken == NULL || strlen(pathToken) == 0){
                 send_with_cwd(client_sock, "Insert path!\n", loggedUser);
            } else {
                // Use "create" logic to validate parent directory (works for new and existing files)
                // up to root
                if (seteuid(0) == -1) {
                    perror("seteuid(0) failed");
                    return;
                }
                // impersonate loggedUser
                if (seteuid(get_uid_by_username(loggedUser)) == -1) {
                    perror("seteuid(user) failed");
                    return;
                }

                 if(resolve_and_check_path(pathToken, loggedCwd, "create")==1){
                    
                    char abs_path[PATH_MAX];
                    char cwd[PATH_MAX];
                    getcwd(cwd, sizeof(cwd));
                    build_abs_path(abs_path, cwd, pathToken);
                    
                    handle_write(client_sock, abs_path, loggedUser, offset);
                    
                } else {
                    send_with_cwd(client_sock, "Error in the file write!\n", loggedUser);
                }

                 // up to root
                if (seteuid(0) == -1) {
                    perror("seteuid(0) failed");
                    return;
                }
                // restore original uid
                if (seteuid(original_uid) == -1) {
                    perror("Error restoring effective UID");
                    return;
                }
            }
        }

      }else if(strcmp(firstToken,"delete")==0){


        if(loggedUser[0]=='\0'){
          send_with_cwd(client_sock, "You are not logged in!\n", loggedUser);
        }else{
          if(secondToken==NULL || strlen(secondToken)==0){
            send_with_cwd(client_sock, "Insert path!\n", loggedUser);
          }else{
            // up to root
            if (seteuid(0) == -1) {
                perror("seteuid(0) failed");
                return;
            }
            // impersonate loggedUser
            if (seteuid(get_uid_by_username(loggedUser)) == -1) {
                perror("seteuid(user) failed");
                return;
            }

            if(resolve_and_check_path(secondToken, loggedCwd, "delete")==1){
              
              if(handle_delete(secondToken)==-1){
                send_with_cwd(client_sock, "Error in the file delete!\n", loggedUser);
              }else{
                send_with_cwd(client_sock, "File deleted successfully!\n", loggedUser);
              }

            }else{
              send_with_cwd(client_sock, "Error in the file delete!\n", loggedUser);
            }

            // up to root
            if (seteuid(0) == -1) {
                perror("seteuid(0) failed");
                return;
            }
            // restore original uid
            if (seteuid(original_uid) == -1) {
                perror("Error restoring effective UID");
                return;
            }
          }//end else second token delete
        }//end else logged user delete
       
        
      }else if(strcmp(firstToken,"transfer_request")==0){
          if(loggedUser[0]=='\0'){
             send_with_cwd(client_sock, "You are not logged in!\n", loggedUser);
          } else {
             // Expecting: transfer_request <file> <dest_user>
             // secondToken = file, thirdToken = dest_user
             if(secondToken == NULL) {
                  send_with_cwd(client_sock, "Usage: transfer_request <file> <user>\n", loggedUser);
             } else {
                 // The prompt implies blocking if dest_user is not logged in.
                 // We pass arguments.
                 char *t_file = secondToken;
                 char *t_user = thirdToken; 
                 // If buffer parsing was loose, ensure we have thirdToken
                 handle_transfer_request(client_sock, t_file, t_user);
             }
          }
      }else if(strcmp(firstToken,"accept")==0){
          if(loggedUser[0]=='\0'){
             send_with_cwd(client_sock, "You are not logged in!\n", loggedUser);
          } else {
              // accept <dir> <id>
              if(!secondToken || !thirdToken) {
                  send_with_cwd(client_sock, "Usage: accept <dir> <id>\n", loggedUser);
              } else {
                  handle_accept(client_sock, secondToken, atoi(thirdToken), loggedUser);
              }
          }
      }else if(strcmp(firstToken,"reject")==0){
          if(loggedUser[0]=='\0'){
             send_with_cwd(client_sock, "You are not logged in!\n", loggedUser);
          } else {
              // reject <id>
              if(!secondToken) {
                  send_with_cwd(client_sock, "Usage: reject <id>\n", loggedUser);
              } else {
                  handle_reject(client_sock, atoi(secondToken), loggedUser);
              }
          }
      }else{
        send_with_cwd(client_sock, "Invalid Command!\n", loggedUser);
      }//end else chmod invalid command

      printf("DEBUG euid end-while: %d\n", geteuid()); // debug
  } // end while

  // Cleanup user from shared memory before exiting
  if(loggedUser[0] != '\0') {
      remove_logged_user(loggedUser);
  }

  close(client_sock);
  printf("Client disconnected\n"); // Debug
  exit(0);                         // ends the child process

} // end function client handler

// Ignores the SIGCHLD signal to avoid zombies
void sigchld_handler(int s) {
  while (waitpid(-1, NULL, WNOHANG) > 0)
    ;
} // end function sigchld_handler

// do not know if it works properly, this function is over testing
int handle_exit(char *buffer) {

  if (strcmp(buffer, "exit\n") == 0) {
    return 1;
  } // end if
  return 0;
} // end handle exit
