// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

#define BUFFER_SIZE 1024 // buffer size for the messages

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "fileSystem.h"
#include "utils.h"

// Global variables
extern uid_t original_uid;
extern gid_t original_gid;
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



// alterantive version of the login fuction, it uses the directory check control

char *login(char *username, int client_socket) {

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
    change_directory(username);
    send_with_cwd(client_socket, "Login successful!\n", username); // send the message to the client

    strncpy(loggedCwd, getcwd(NULL, 0), sizeof(loggedCwd)-1);
    loggedCwd[sizeof(loggedCwd)-1] = '\0';

    // back to non-root
    if (seteuid(original_uid) == -1) {
      perror("seteuid(original_uid) failed");
      return NULL;

    } // end if

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

  // create the user's home directory
  if (!create_directory(username, strtol(permissions, NULL, 8))) {

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

/*This function is a the main function that handles the client,
as we can see it has different behaviuors based on the message received  */
void handle_client(int client_sock) {

  char buffer[BUFFER_SIZE];
  int n;

  

  while ((n = read(client_sock, buffer, BUFFER_SIZE - 1)) > 0) {
   
    buffer[n] = '\0'; /*Terminates the buffer, maybe we can consider this as a
    buffer overflow security measure ?
    */
    printf("Client: %s",
           buffer); // print the message received from the client, server side
    // write(client_sock, buffer, n); //send the message to the client

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

      char *tmp = login(secondToken, client_sock);

      // if the login is successful we store the username in the loggedUser variable
      if(tmp!=NULL){
        strncpy(loggedUser, tmp, sizeof(loggedUser)-1);
        loggedUser[sizeof(loggedUser)-1] = '\0';
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

            if(create_directory(secondToken,strtol(thirdToken, NULL, 8))==1){
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

            if(create_file(secondToken,strtol(thirdToken, NULL, 8))==1){
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
            if(resolve_and_check_path(secondToken, loggedCwd, "cd")==1 && change_directory(secondToken)==1){
              send_with_cwd(client_sock, "Directory changed successfully!\n", loggedUser);
            }else{
              send_with_cwd(client_sock, "Error in the directory change!\n", loggedUser);
            }
            
          }//end else secondToken

        }//end else loggedUser cd
    } else {
      if(strcmp(firstToken,"list")==0){
        if(loggedUser[0]=='\0'){
          send_with_cwd(client_sock, "You are not logged in!\n", loggedUser);
        }else{//here we have to implement the sandbox check
          char out[8192];
          if(secondToken==NULL || strlen(secondToken)==0){
            
            list_directory_string(".", out, sizeof(out));
          }else{
            if(resolve_and_check_path(secondToken, loggedCwd, "list")==1){
              list_directory_string(secondToken, out, sizeof(out));
              send_with_cwd(client_sock, out, loggedUser);
            }else{
              send_with_cwd(client_sock, "Error in the directory listing!\n", loggedUser);
            }//end else directory listing
          }//end else secondToken
         
          
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

               //call function 
               send_with_cwd(client_sock, "test senza background!\n", loggedUser);
              }else{
                send_with_cwd(client_sock, "Error in the file upload!\n", loggedUser);
              }
              
            }else{
              //if i am here i have to perform this operation in background
              if(resolve_and_check_path(thirdToken, loggedCwd, "upload")==1 && strcmp(fourthToken,"-b")==0){
                //call the function with background
                send_with_cwd(client_sock, "test con background!", loggedUser);
              }else{
                send_with_cwd(client_sock, "Error in the file upload!", loggedUser);
              }
            }//end else fourthToken
          }//end else thirdToken
          
        }//end else secondToken
      }//end else loggedUser upload
    }else{
        send_with_cwd(client_sock, "Invalid Command!\n", loggedUser);
      }//end else list invalid command
    }// end else login
  } // end while


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
