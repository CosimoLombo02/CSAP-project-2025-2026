#include "clientsHandler.h"
#include "serverFunctions.h"
#include "lockServer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <signal.h>

/*This function is a the main function that handles the client,
as we can see it has different behaviuors based on the message received  */
void handle_client(int client_sock, int port) {

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
        if (errno == ECONNRESET) {
        break;
    }
        perror("read error");
        break;
    } 
    if (n == 0) {
        break; // Client disconnected
    }
   
    buffer[n] = '\0'; /*Terminates the buffer, maybe we can consider this as a
    buffer overflow security measure ?
    */
    printf("Client (Port %d): %s",
           port, buffer); // print the message received from the client, server side
    // write(client_sock, buffer, n); //send the message to the client

    //printf("DEBUG start-while euid: %d\n", geteuid());

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
                    printf("Waking up PID %d waiting for %s\n", shared_state->waiters[i].pid, loggedUser); // Notify the server that we are waiting for the user to connect
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

            if( resolve_and_check_path(secondToken, loggedCwd, "create")==1){
               char abs_path[PATH_MAX];
               char cwd[PATH_MAX];
               getcwd(cwd, sizeof(cwd));
               // Pass CWD as base for relative paths
               build_abs_path(abs_path, cwd, secondToken);
               
               if(create_directory(abs_path,strtol(thirdToken, NULL, 8))==1){
                  send_with_cwd(client_sock, "Directory created successfully!\n", loggedUser);
               } else {
                  send_with_cwd(client_sock, "Error in the directory creation!\n", loggedUser);
               }
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
            
            if( resolve_and_check_path(secondToken, loggedCwd, "create")==1 ){
               char abs_path[PATH_MAX];
               char cwd[PATH_MAX];
               getcwd(cwd, sizeof(cwd));
               build_abs_path(abs_path, cwd, secondToken);
               
               if(create_file(abs_path,strtol(thirdToken, NULL, 8))==1){
                  send_with_cwd(client_sock, "File created successfully!\n", loggedUser);
               } else {
                  send_with_cwd(client_sock, "Error in the file creation!\n", loggedUser);
               }
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

            if(resolve_and_check_path(secondToken, loggedCwd, "cd")==1){
               char abs_path[PATH_MAX];
               char cwd[PATH_MAX];
               getcwd(cwd, sizeof(cwd));
               build_abs_path(abs_path, cwd, secondToken);
               if(change_directory(abs_path)==1){
                  send_with_cwd(client_sock, "Directory changed successfully!\n", loggedUser);
               }else{
                  send_with_cwd(client_sock, "Error in the directory change!\n", loggedUser);
               }
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
              char abs_path[PATH_MAX];
              char cwd[PATH_MAX];
              getcwd(cwd, sizeof(cwd));
              build_abs_path(abs_path, cwd, secondToken);
              list_directory_string(abs_path, out, sizeof(out));
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
              
              // Impersonate user for path resolution
              if (seteuid(0) == -1) { perror("seteuid(0)"); return; }
              if (seteuid(get_uid_by_username(loggedUser)) == -1) { perror("seteuid(user)"); return; }

              int path_valid = resolve_and_check_path(thirdToken, loggedCwd, "upload");

              // Back to root for handle_upload (it needs to chown)
              if (seteuid(0) == -1) { perror("seteuid(0)"); return; }

              if(path_valid == 1){
               char abs_path[PATH_MAX];
               char cwd[PATH_MAX];
               getcwd(cwd, sizeof(cwd));
               build_abs_path(abs_path, cwd, thirdToken);
               handle_upload(client_sock, abs_path, secondToken, loggedUser, get_uid_by_username(loggedUser), get_gid_by_username(loggedUser));
              }else{
                send_with_cwd(client_sock, "Error in the file upload!\n", loggedUser);
              }
              
              // Back to original_uid
              if (seteuid(original_uid) == -1) {
                perror("seteuid(original_uid) failed");
                return;
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
                
                // Impersonate user for path resolution
                if (seteuid(0) == -1) { perror("seteuid(0)"); return; }
                if (seteuid(get_uid_by_username(loggedUser)) == -1) { perror("seteuid(user)"); return; }

                int path_valid = resolve_and_check_path(secondToken, loggedCwd, "download");

                // Check succeeded as user?
                if(path_valid == 1){
                  // We are already USER here.
                  char abs_path[PATH_MAX];
                  char cwd[PATH_MAX];
                  getcwd(cwd, sizeof(cwd));
                  build_abs_path(abs_path, cwd, secondToken);
                  handle_download(client_sock, abs_path, loggedUser);
                }else{
                    send_with_cwd(client_sock, "Error in the file download!\n", loggedUser);
                }

                // Restore
                if (seteuid(0) == -1) { perror("seteuid(0)"); return; }
                if (seteuid(original_uid) == -1) { perror("seteuid(orig)"); return; }

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
            
            // Impersonate
            if (seteuid(0) == -1) { perror("seteuid(0)"); return; }
            if (seteuid(get_uid_by_username(loggedUser)) == -1) { perror("seteuid(user)"); return; }

            int path_valid = resolve_and_check_path(secondToken, loggedCwd, "chmod");

            if(path_valid == 1){
              if(check_permissions(thirdToken)==0){
                  send_with_cwd(client_sock, "Invalid permissions!\n", loggedUser);
              }else{
                // handle_chmod calls open(O_RDONLY) then fchmod. 
                // User owns file, so can fchmod.
                char abs_path[PATH_MAX];
                char cwd[PATH_MAX];
                getcwd(cwd, sizeof(cwd));
                build_abs_path(abs_path, cwd, secondToken);
                
                if(handle_chmod(abs_path, thirdToken)==-1){
                  send_with_cwd(client_sock, "Error in the file chmod!\n", loggedUser);
                }else{
                  send_with_cwd(client_sock, "File chmod successfully!\n", loggedUser);
                }
              }
            }else{
              send_with_cwd(client_sock, "Error in the file chmod!\n", loggedUser);
            }
            
            // Restore
            if (seteuid(0) == -1) { perror("seteuid(0)"); return; }
            if (seteuid(original_uid) == -1) { perror("seteuid(orig)"); return; }

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
              
               // Impersonate
               if (seteuid(0) == -1) { perror("seteuid(0)"); return; }
               if (seteuid(get_uid_by_username(loggedUser)) == -1) { perror("seteuid(user)"); return; }

               int p1 = resolve_and_check_path(secondToken, loggedCwd, "move");
               int p2 = resolve_and_check_path(thirdToken, loggedCwd, "move");
               
               if(p1 == 1 && p2 == 1) {
                  char old_abs[PATH_MAX];
                  char new_abs[PATH_MAX];
                  
                  getcwd(cwd, sizeof(cwd));

                  // build absolute paths
                  build_abs_path(old_abs, cwd, secondToken);
                  build_abs_path(new_abs, cwd, thirdToken);

                  if(is_file_locked_by_transfer(old_abs)) {
                      send_with_cwd(client_sock, "Error in the file mv!\n", loggedUser);
                  } else {
                      if(handle_mv(old_abs, new_abs)==-1){
                        send_with_cwd(client_sock, "Error in the file mv!\n", loggedUser);
                      }else{
                        send_with_cwd(client_sock, "File moved successfully!\n", loggedUser);
                      }
                  }
               } else {
                   send_with_cwd(client_sock, "Error in the file mv!\n", loggedUser);
               }
               
               // Restore
               if (seteuid(0) == -1) { perror("seteuid(0)"); return; }
               if (seteuid(original_uid) == -1) { perror("seteuid(orig)"); return; }
               
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
                      
                    // Check locks before write
                    if(is_file_locked_by_transfer(abs_path)) {
                        send_with_cwd(client_sock, "Error in the file write!\n", loggedUser);
                    } else {
                        handle_write(client_sock, abs_path, loggedUser, offset);
                    }
                    
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
              
              // Check locks
              char abs_path[PATH_MAX];
              // resolve_and_check_path verifies existence but doesn't give us the absolute path easily
              // We can construct it since we are in loggedCwd (or resolve it again)
              // Actually resolve_and_check_path operates on arg.
              // Let's resolve properly to check lock
              getcwd(cwd, sizeof(cwd));
              build_abs_path(abs_path, cwd, secondToken); // Use CWD
              
              if(is_file_locked_by_transfer(abs_path)) {
                   send_with_cwd(client_sock, "Error in the file delete!\n", loggedUser);
              } else {
                  if(handle_delete(abs_path)==-1){
                    send_with_cwd(client_sock, "Error in the file delete!\n", loggedUser);
                  }else{
                    send_with_cwd(client_sock, "File deleted successfully!\n", loggedUser);
                  }
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

      //printf("DEBUG euid end-while: %d\n", geteuid());
  } // end while

  // Cleanup user from shared memory before exiting
  if(loggedUser[0] != '\0') {
      remove_logged_user(loggedUser);
  }

  close(client_sock);
  printf("Client disconnected port : %d\n", port);
  exit(0);                         // ends the child process

} // end function client handler
