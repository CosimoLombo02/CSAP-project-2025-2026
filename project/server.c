// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

#define BUFFER_SIZE 1024 // buffer size for the messages

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

// Global variables
uid_t original_uid = 0;
gid_t original_gid = 0;
char root_directory[PATH_MAX];
char original_cwd[PATH_MAX];
char start_cwd[PATH_MAX];

// the client is handled by specific functions in serverFunctions.h
int main(int argc, char *argv[]) {

  strncpy(start_cwd, getcwd(original_cwd, PATH_MAX), PATH_MAX);

  // get the uid and gid of the user that started the server
  const char *sudo_uid = getenv("SUDO_UID");
  const char *sudo_gid = getenv("SUDO_GID");

  if (sudo_uid != NULL && sudo_gid != NULL && geteuid() == 0) {
    // server was launched with sudo: original user is SUDO_UID/SUDO_GID
    original_uid = (uid_t)strtol(sudo_uid, NULL, 10);
    original_gid = (gid_t)strtol(sudo_gid, NULL, 10);
    setgid(original_gid);

  } else {
    // no sudo: fallback to current uid/gid
    original_uid = getuid();
    original_gid = getgid();
    printf("Running without sudo!\n");
    exit(1);
  }

  // default values
  char *server_ip = "127.0.0.1";
  int port = 8080;
  char *root_dir = "./csap_root";

  // local buffer for exit
  char buffer[BUFFER_SIZE];

  // params are mandatory
  if (argc != 4) {
    printf("Needs params!");
    exit(1);
  } // end if

  // the first argument is the root directory, the second one is the ip address,
  // the third one is the port
  if (argc >= 2)
    root_dir = argv[1];
  if (argc >= 3)
    server_ip = argv[2];
  if (argc >= 4)
    port = atoi(argv[3]);

  if (check_directory(root_dir) == 0) {
    if (create_directory(root_dir, 0755) ==
        0) { // create the directory with rwx permissions for the owner and
             // group
      // the first 0 is for the octal number
      perror("Error in the directory creation!");
      exit(1);
    } // end if
  } // end if

  // copy the root directory into the global variable
  strncpy(root_directory, root_dir, PATH_MAX);
  root_directory[PATH_MAX - 1] = '\0'; // Ensure null-termination

  //change to root directory
  if (change_directory(root_dir) == 0) {
    perror("Error in the directory change!");
    exit(1);
  } // end if

  getcwd(original_cwd, PATH_MAX);

  // set the uid and gid of the server
  seteuid(original_uid);

  // create the socket
  int server_sock = socket(AF_INET, SOCK_STREAM, 0);

  if (server_sock < 0) {
    perror("Error in the socket creation!");
    return 1; // exit
  } // end if

  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
    perror("Invalid address/ Address not supported");
    return 1; // exit
  } // end if

  // If we are here we can perform binding
  if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
      0) {
    perror("Error in the binding!");
    return 1; // exit
  } // end if

  // listen to the socket
  if (listen(server_sock, 3) < 0) {
    perror("Error in the listen!");
    return 1; // exit
  } // end if

  // signal handler for the child process
  signal(SIGCHLD, sigchld_handler);

  // Debug, if I am here the binding is working correctly
  printf("Server working on ip: %s and port %d\n", server_ip, port);

  fd_set readfds;
  int max_sd = server_sock;

  // Server services
  while (1) {

    // This is implemented for listening both the server socket and the standard
    // input
    FD_ZERO(&readfds);
    FD_SET(server_sock, &readfds);
    FD_SET(STDIN_FILENO, &readfds);

    // wait for an activity on one of the sockets
    int activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);


    // NOTE:
    // select() can be interrupted by signals (e.g., SIGCHLD when a child exits).
    // In that case it returns -1 and sets errno = EINTR, but the fd_sets are no
    // longer reliable for checking FD_ISSET(). If we simply continued and used
    // readfds anyway, we might think that server_sock or STDIN_FILENO are ready
    // when they are not, and then:
    //   - call accept() on the listening socket and block, or
    //   - call read() on STDIN and block the main server loop.
    // To avoid this, when errno == EINTR we just restart the loop, rebuild the
    // fd_sets, and call select() again on a clean state.
    if (activity < 0) {
      if (errno == EINTR) {
        // select was interrupted by a signal (e.g. SIGCHLD for a child that terminates)
        // simply restart the loop
        continue;
      } else {
        perror("select error");
        break;   // or exit(1); if you prefer to exit
      }
    }//end if activity


    // If something happened on the standard input
    if (FD_ISSET(STDIN_FILENO, &readfds)) {
      if (fgets(buffer, BUFFER_SIZE, stdin) != NULL) {
        // check for exit command
        if (strcmp(buffer, "exit\n") == 0) {
          printf("Server exiting...\n");
          kill(0, SIGTERM);
          break;
        } // end if exit
      } // end if
    } // end if

    // If something happened on the server socket, then its an incoming
    // connection
    if (FD_ISSET(server_sock, &readfds)) {
      struct sockaddr_in client_addr;
      socklen_t addr_len = sizeof(client_addr);
      int client_sock =
          accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);

      if (client_sock < 0) {
        perror("Error in the accept!");
        continue;
      } // end if

      // Debug, if I am here the accept is working correctly
      printf("Client connected from ip: %s and port %d\n",
             inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

      // Now we can handle the client
      pid_t pid = fork();
      if (pid < 0) {
        perror("Error in the fork!");
        close(client_sock);
      } // end if
      else {
        if (pid == 0) {
          close(server_sock); // child closes server socket
          handle_client(client_sock);
          close(client_sock);
          exit(0);
        } else {
          close(client_sock);
        } // end nested else
      } // end else
    } // end if socket
  } // end while

  close(server_sock); // closes the server socket
  return 0;

} // end main
