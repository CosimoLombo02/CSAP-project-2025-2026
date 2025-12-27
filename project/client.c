// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include "clientFunctions.h"
#include "uploadDownloadClient.h"

char original_cwd[PATH_MAX];




int main(int argc, char *argv[]) {

  // default values
  char *server_ip = "127.0.0.1";
  int port = 8080;

  // params are mandatory
  if (argc != 3) {
    printf("Needs params!");
    exit(1);
  }

  // overwrite if passed as parameters
  if (argc >= 2)
    server_ip = argv[1];
  if (argc >= 3)
    port = atoi(argv[2]);

  int sock = socket(AF_INET, SOCK_STREAM, 0);
  
  signal(SIGCHLD, sigchld_handler);
  if (sock < 0) {
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

  if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    perror("Connection failed");
    return 1; // exit
  } // end if

  // If I am here the connection is working correctly
  printf("Connected to server at %s:%d\n", server_ip, port);

  char buffer[BUFFER_SIZE];
  char pending_user[64] = "";

    // Initialize file descriptor set
    fd_set readfds;
    int max_sd = sock;

    printf("<");
    fflush(stdout);

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);

        // Wait for activity
        if (select(max_sd + 1, &readfds, NULL, NULL, NULL) < 0) {
           if (errno == EINTR) continue;
           perror("select");
           break;
        }

        // 1. Check for Asynchronous Notification
        if (FD_ISSET(sock, &readfds)) {
            int n = read(sock, buffer, BUFFER_SIZE - 1);
            if (n <= 0) {
                 printf("\nServer disconnected\n");
                 break;
            }
            buffer[n] = '\0';
            // Print notification (likely starts with \n or [!])
            // We overwrite the current prompt line
            printf("\r%s", buffer);
            // Reprint prompt if not contained
            if (strstr(buffer, "> ") == NULL) {
                printf("\n<");
            }
            fflush(stdout);
            continue; 
        }

        // 2. Check for User Input
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            if (fgets(buffer, BUFFER_SIZE, stdin) == NULL) break;
            
            // --- EXISTING COMMAND LOGIC STARTS HERE ---
            
            // Capture potential login username
            if (strncmp(buffer, "login ", 6) == 0) {
                sscanf(buffer, "login %s", pending_user);
            } else {
                pending_user[0] = '\0';
            }

            // Check for -b flag in upload command
            char cmd_copy[BUFFER_SIZE];
            strcpy(cmd_copy, buffer);
            cmd_copy[strcspn(cmd_copy, "\r\n")] = '\0';
            
            char *t1 = strtok(cmd_copy, " ");
            char *t2 = strtok(NULL, " "); // client path
            char *t3 = strtok(NULL, " "); // server path
            char *t4 = strtok(NULL, " "); // -b flag if present

           if (t1 && strcmp(t1, "upload") == 0 && t4 && strcmp(t4, "-b") == 0) {
                pid_t pid = fork();
                if (pid < 0) {
                    perror("fork");
                } else if (pid > 0) {
                    printf("Background upload started...\n%s", current_prompt);
                    add_operation(pid, OP_UPLOAD, t3, t2); // t2=client, t3=server
                    continue; 
                } else {
                     // Child process
                     close(sock); // close parent socket
                     int new_sock = socket(AF_INET, SOCK_STREAM, 0);
                     if (new_sock < 0) exit(1);

                     if (connect(new_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                        perror("Background connection failed");
                        exit(1);
                     }
                     
                     // Auto-login if user was logged in
                     if (strlen(logged_user) > 0) {
                         char login_cmd[128];
                         snprintf(login_cmd, sizeof(login_cmd), "login %s\n", logged_user);
                         write(new_sock, login_cmd, strlen(login_cmd));
                         
                         // Consume login response
                         char tmp[BUFFER_SIZE];
                         read(new_sock, tmp, BUFFER_SIZE-1);
                     }
                     
                     // Send upload command without -b
                     char up_cmd[BUFFER_SIZE];
                     snprintf(up_cmd, sizeof(up_cmd), "upload %s %s\n", t2, t3);
                     write(new_sock, up_cmd, strlen(up_cmd));
                     
                     // Handle response
                     char buf2[BUFFER_SIZE];
                     int n2 = read(new_sock, buf2, BUFFER_SIZE-1);
                     if (n2 > 0) {
                         buf2[n2] = '\0';
                         // Check if server says "You are not logged in!"
                         if (strstr(buf2, "not logged in") != NULL) {
                             close(new_sock);
                             exit(101); // Not logged in
                         }

                         buf2[strcspn(buf2, "\r\n")] = '\0'; // Remove newline
                         char *fToken = strtok(buf2, " ");
                         char *sToken = strtok(NULL, " ");
                         
                         if (sToken && strcmp(sToken, "READY!") == 0) {
                             if (access(t2, R_OK) == 0) {
                                 send(new_sock, "OK\n", 3, 0);
                                 client_upload(t2, new_sock, logged_user);
                                 
                                 // Manually read response (silent check)
                                 char response[4096] = {0};
                                 read(new_sock, response, sizeof(response) - 1);
                                 
                                 close(new_sock);
                                 exit(0); // Success
                             } else {
                                 send(new_sock, "ERR\n", 4, 0);
                                 close(new_sock);
                                 exit(102); // File error
                             }
                         } else {
                             // Some other error from server
                             close(new_sock);
                             exit(103);
                         }
                     }
                     close(new_sock);
                     exit(1); // Generic error if read failed
                }
           }
           
           // Background Download Logic
           if (t1 && strcmp(t1, "download") == 0 && t4 && strcmp(t4, "-b") == 0) {
               pid_t pid = fork();
                if (pid < 0) {
                    perror("fork");
                } else if (pid > 0) {
                    printf("Background download started...\n%s", current_prompt);
                    add_operation(pid, OP_DOWNLOAD, t2, t3); // t2=server, t3=client
                    continue; 
                } else {
                     // Child process
                     close(sock);
                     int new_sock = socket(AF_INET, SOCK_STREAM, 0);
                     if (new_sock < 0) exit(1);

                     if (connect(new_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                        exit(1);
                     }
                     
                     // Auto-login
                     if (strlen(logged_user) > 0) {
                         char login_cmd[128];
                         snprintf(login_cmd, sizeof(login_cmd), "login %s\n", logged_user);
                         write(new_sock, login_cmd, strlen(login_cmd));
                         char tmp[BUFFER_SIZE];
                         read(new_sock, tmp, BUFFER_SIZE-1);
                     }
                     
                     // Send download command without -b
                     char dw_cmd[BUFFER_SIZE];
                     snprintf(dw_cmd, sizeof(dw_cmd), "download %s %s\n", t2, t3);
                     write(new_sock, dw_cmd, strlen(dw_cmd));
                     
                     // Handle response
                     // Server sends "READY!" if OK
                     char buf2[BUFFER_SIZE];
                     int n2 = read(new_sock, buf2, BUFFER_SIZE-1);
                     if (n2 > 0) {
                         buf2[n2] = '\0';
                         if (strstr(buf2, "not logged in") != NULL) { close(new_sock); exit(101); }
                         // Check for "READY!"
                         if (strstr(buf2, "READY!") != NULL) {
                             // Call client_download to receive data
                             if(client_download(t2, t3, new_sock) == 0) {
                                 close(new_sock);
                                 exit(0);
                             } else {
                                 close(new_sock);
                                 exit(103); 
                             }
                         } else {
                             // Server said "File not found" or something
                             close(new_sock);
                             exit(102); 
                         }
                     }
                     close(new_sock);
                     exit(1);
                }
           }


            /*if the user types exit the client terminates,
            but this is just a prototype, we have to handle the
            -b option as the professor wrote on the slides
            */
            if (strcmp(buffer, "exit\n") == 0) {
              if (active_operations != NULL) {
                  printf("Background operations pending... cannot exit.\n%s", current_prompt);
                  continue;
              }
              printf("Bye!\n"); // output on the console
              break;
            } // end if

            // Save command context because buffer will be overwritten by response
            char command_copy[BUFFER_SIZE];
            strncpy(command_copy, buffer, BUFFER_SIZE - 1);
            command_copy[BUFFER_SIZE - 1] = '\0';
            command_copy[strcspn(command_copy, "\r\n")] = '\0';

            // send to the server
            if (write(sock, buffer, strlen(buffer)) < 0) {
              perror("Error in the write!");
              break;
            } // end if

            // receive from the server 
            int n = read(sock, buffer, BUFFER_SIZE - 1);
            if (n < 0) {
              perror("Error in the read!");
              break;
            } // end if
            else {
              if (n == 0) {
                printf("Server disconnected\n");
                break; // the client terminates
              } // end if
            } // end else
            buffer[n] = '\0';     // string terminator
            update_prompt(buffer);
            
            // Check if we need to handle specific responses based on the command we sent
            char *c1 = strtok(command_copy, " ");
            char *c2 = strtok(NULL, " "); // server path (for download) or local path (for upload)
            char *c3 = strtok(NULL, " "); // client path (for download) or remote path (for upload)
            
            if (c1 && strcmp(c1, "read") == 0) {
                 if (strstr(buffer, "READY!") != NULL) {
                     client_read(sock);
                     
                     // The server sends the prompt after the file content
                     char prompt_buf[BUFFER_SIZE];
                     int n_prompt = read(sock, prompt_buf, BUFFER_SIZE-1);
                     if (n_prompt > 0) {
                         prompt_buf[n_prompt] = '\0';
                         update_prompt(prompt_buf);
                         printf("\n%s", prompt_buf);
                     }
                     continue;
                 }
            }
            
            // Write command handling
            if (c1 && strcmp(c1, "write") == 0) {
                if (strstr(buffer, "READY!") != NULL) {
                    client_write(sock);
                     // Wait for final response
                     char resp_buf[BUFFER_SIZE];
                     int n_resp = read(sock, resp_buf, BUFFER_SIZE - 1);
                     if (n_resp > 0) {
                         resp_buf[n_resp] = '\0';
                         update_prompt(resp_buf);
                         printf("%s", resp_buf);
                     }
                     continue;
                }
            }

            
            if (c1 && strcmp(c1, "download") == 0 && c2 && c3) {
                // Foreground download
                // Check if server said "READY!"
                if (strstr(buffer, "READY!") != NULL) {
                    // Call client_download
                    if (client_download(c2, c3, sock) == 0) {
                        printf("Download of %s completed.\n", c2);
                         char prompt_buf[BUFFER_SIZE];
                         int n = read(sock, prompt_buf, BUFFER_SIZE-1);
                         if(n > 0) {
                             prompt_buf[n] = '\0';
                             update_prompt(prompt_buf);
                             printf("%s", prompt_buf);
                         }
                    } else {
                        send(sock, "ERR\n", 4, 0);
                        int n = recv(sock, buffer, BUFFER_SIZE - 1, 0);
                        if (n > 0) {
                            buffer[n] = '\0';
                            update_prompt(buffer);
                            printf("%s", buffer);
                        }
                    }
                    continue; // Skip the standard printf and parsing below
                }
            }

            printf("%s", buffer); // Debug

            if (strstr(buffer, "Login successful!") != NULL && strlen(pending_user) > 0) {
                strcpy(logged_user, pending_user);
            }



            buffer[strcspn(buffer, "\r\n")] = '\0';

            char *firstToken = strtok(buffer, " ");
            char *secondToken = strtok(NULL, " ");
            
            if (secondToken && strcmp(secondToken, "READY!") == 0 && firstToken) {
                if (access(firstToken, R_OK) == 0) {
                    send(sock, "OK\n", 3, 0);         
                   if(client_upload(firstToken, sock, logged_user)==0){
                     // Manually read response (foreground)
                    char response[4096] = {0};
                    if (read(sock, response, sizeof(response) - 1) > 0) {
                        update_prompt(response);
                        printf("%s", response);
                    }//end nested if
            
                   }//end client upload check
            
                   
                } else {
                    send(sock, "ERR\n", 4, 0);    
            
                    // receive from the server 
                    int n = read(sock, buffer, BUFFER_SIZE - 1);
                    if (n < 0) {
                      perror("Error in the read!");
                      break;
                    } // end if
                    else {
                      if (n == 0) {
                        printf("Server disconnected\n");
                        break; // the client terminates
                      } // end if
                    } // end else
                    buffer[n] = '\0';     // string terminator
                    printf("%s", buffer); // Debug
                
                }//end else access
            }//end if secondToken

      } // end FD_ISSET(STDIN)
  } // end while(1) select
  close(sock); // closes the socket
  return 0;

} // end main