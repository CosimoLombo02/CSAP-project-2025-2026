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

/*This function is a kind of login, if the username exits
in the file users.txt it sends a success message to the client, otherwise
it sends a failure message */
/*char* login(char *username,int client_sock){

    //check if the username is null or made only by spaces
    if(username == NULL || strlen(username) == 0){
        write(client_sock, "Insert Username!\n", strlen("Insert Username!\n"));
//send the message to the client return NULL;
    }//end if

    FILE *f = fopen("users.txt", "r");
    if(f == NULL){
        perror("Error in the file opening!");
       // exit(1);
       return NULL;
    }//end if

    char line[BUFFER_SIZE];
    while(fgets(line, BUFFER_SIZE, f) != NULL){

        line[strcspn(line, "\n")] = '\0'; //remove the newline character
      //  line[strcspn(line, "\r\n")] = '\0'; // rimuove newline

        if(strcmp(line, username) == 0){
             write(client_sock, "Login successful!\n", strlen("Login
successful!\n")); //send the message to the client fclose(f); return username ;
        }//end if

    }//end while

    //If I am here the username does not exist
    write(client_sock, "Login failed!\n", strlen("Login failed!\n")); //send the
message to the client

fclose(f);
return NULL ;

}//end function login
*/

// alterantive version of the login fuction, it uses the directory check control

char *login(char *username, int client_socket) {

  // check if the username is null or made only by spaces
  if (username == NULL || strlen(username) == 0) {
    write(client_socket, "Insert Username!\n",
          strlen("Insert Username!\n")); // send the message to the client
    return NULL;
  } // end if

  // PATH_MAX is a constant defined in limits.h
  char path[PATH_MAX];

  size_t root_len = strlen(root_directory); // length of the root directory
  size_t user_len = strlen(username);       // length of the username

  // check if the path is too long
  if (root_len + 1 + user_len + 1 > sizeof(path)) {
    write(client_socket, "Error: path too long\n",
          strlen("Error: path too long\n"));
    return NULL;
  }

  // create the path to the user's home directory
  snprintf(path, root_len + 1 + user_len + 1, "%s/%s", root_directory,
           username);

  // up to root
  if (seteuid(0) == -1) {
    perror("seteuid(0) failed");
    return NULL;
  } // end if

  if (check_directory(path) == 1) {
    write(client_socket, "Login successful!\n",
          strlen("Login successful!\n")); // send the message to the client

    // back to non-root
    if (seteuid(original_uid) == -1) {
      perror("seteuid(original_uid) failed");
      return NULL;

    } // end if

    return username;

  } else {
    write(client_socket, "Login failed!\n",
          strlen("Login failed!\n")); // send the message to the client

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
    write(client_sock, "Insert Username!\n",
          strlen("Insert Username!\n")); // send the message to the client
    return;
  } // end if

  if (permissions == NULL || strlen(permissions) == 0) {
    write(client_sock, "Insert Permissions!\n",
          strlen("Insert Permissions!\n")); // send the message to the client
    return;
  } // end if

  // Here we write the username in the file users.txt
  /* FILE *f = fopen("users.txt", "a");
   if(f == NULL){
       //perror("Error in the file opening!");
       write(client_sock, "Error in the file opening!\n", strlen("Error in the
   file opening!\n")); //send the message to the client
       //exit(1);
   }//end if
   */

  // check if the username already exists
  /*if(check_username(username) == 1){
       write(client_sock, "Username already exists!\n", strlen("Username already
   exists!\n")); //send the message to the client return;
   }//end if */

  // check if the permission are valid
  if (strlen(permissions) != 3) {
    write(client_sock,
          "Invalid Permissions (max 3 numbers and each number must be between "
          "0 and 7 )!\n",
          strlen("Invalid Permissions (max 3 numbers and each number must be "
                 "between 0 and 7 )!\n")); // send the message to the client
    return;
  } // end if

  if (check_permissions(permissions) == 0) {
    write(client_sock, "Invalid Permissions!\n",
          strlen("Invalid Permissions!\n")); // send the message to the client
    return;
  } // end if

  // creation of the real user in the system
  if (create_system_user(username) == 0) {
    write(
        client_sock, "Error in the user creation!\n",
        strlen(
            "Error in the user creation!\n")); // send the message to the client
    return;
  } // end if

  // char * path = strcat("./", username); //create the path to the user's home
  // directory create_directory(path,strtol(permissions, NULL, 8));   //create
  // the user's home directory

  /*fprintf(f, "%s", "\n"); //insert new line
   fprintf(f, "%s", username); //write the username in the file
   fclose(f); //close the file*/

  char path[PATH_MAX];

  size_t root_len = strlen(root_directory); // length of the root directory
  size_t user_len = strlen(username);       // length of the username

  // check if the path is too long
  if (root_len + 1 + user_len + 1 > sizeof(path)) {
    write(client_sock, "Error: path too long\n",
          strlen("Error: path too long\n"));
    return;
  } // end if

  snprintf(path, root_len + 1 + user_len + 1, "%s/%s", root_directory,
           username); // create the path to the user's home directory

  // up to root
  if (seteuid(0) == -1) {
    perror("seteuid(0) failed");
    return;
  } // end if

  // create the user's home directory
  if (!create_directory(path, strtol(permissions, NULL, 8))) {

    // if create_directory fails, we restore the original uid
    if (seteuid(original_uid) == -1) {
      perror("Error restoring effective UID");
      return;
    } // end if
    write(client_sock, "Error in the home directory creation!\n",
          strlen("Error in the home directory creation!\n"));
    return;
  } // end if

  chown(path, get_uid_by_username(username),
        original_gid); // changes the owner and group of the directory

  if (seteuid(original_uid) == -1) {
    perror("Error restoring effective UID");
    return;
  } // end if

  write(
      client_sock, "User created successfully!\n",
      strlen("User created successfully!\n")); // send the message to the client

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

    // printf("%d\n",strcmp(firstToken,"login")); //Debug

    if (strcmp("login", firstToken) == 0) {

      char *loggedUser = login(secondToken, client_sock);

    } else {
      if (strcmp("create_user", firstToken) == 0) {

        // call the function for creating the user
        create_user(secondToken, thirdToken, client_sock);

      } else {
        // if i am here, the user input is invalid
        write(client_sock, "Invalid Command!\n", strlen("Invalid Command!\n"));
      } // end nested else

    } // end else

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
