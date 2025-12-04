// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

#include <dirent.h>
#include <grp.h>
#include <pwd.h>

// this functions checks if the username exists
// 0 not exists, 1 exists
// probably useless
/*int check_username(char* username){

    //just to be sure
    if(username == NULL || strlen(username) == 0){
        return 0;
    }//end if

   FILE *f = fopen("users.txt", "r");
    if(f == NULL){
        perror("Error in the file opening!");
       // exit(1);
       return 0;
    }//end if


    char line[BUFFER_SIZE];
    while(fgets(line, BUFFER_SIZE, f) != NULL){

        line[strcspn(line, "\n")] = '\0'; //remove the newline character
      //  line[strcspn(line, "\r\n")] = '\0'; // rimuove newline

        if(strcmp(line, username) == 0){

             fclose(f);
            return 1;
        }//end if

    }//end while



fclose(f);
return 0;

}//end check_username
*/

// this functions checks if the permissions are valid
// 0 not valid , 1 valid

int check_permissions(char *permissions) {
  if (permissions[0] >= '0' && permissions[0] <= '7') {
    if (permissions[1] >= '0' && permissions[1] <= '7') {
      if (permissions[2] >= '0' && permissions[2] <= '7') {
        return 1;
      } // end if
    } // end if
  } // end if

  return 0;

} // end check permissions

// check if a directory exists
int check_directory(char *path) {

  DIR *d = opendir(path);
  if (d) {
    closedir(d); // close the directory
    return 1;    // the directory exists
  }
  return 0;
} // end check_directory

// this function checks if the username exists
// 0 not exists, 1 exists
int check_username(char *username) {
  char path[512]; // buffer sufficientemente grande

  // Copia "./" nel buffer
  strcpy(path, "./");

  // Aggiunge il nome utente
  strncat(path, username, sizeof(path) - strlen(path) - 1);

  // Ora path = "./username"
  return check_directory(path);
} // end check_username

// this function gets the group of the user
// that runs the program
char *get_group() {
  gid_t g = getgid();
  struct group *grp = getgrgid(g);
  return grp->gr_name;
} // end get_group

uid_t get_uid_by_username(char *username) {
  if (username == NULL) {
    errno = EINVAL; // argoment not valid
    return (uid_t)-1;
  } // end if

  struct passwd *pwd = getpwnam(username);
  if (pwd == NULL) {
    // user not found
    return (uid_t)-1;
  } // end if

  return pwd->pw_uid;
} // end get_uid_by_username

// this function gets the groud id of a user
// giving a username

gid_t get_gid_by_username(char *username) {

  if (username == NULL) {
    errno = EINVAL; // argoment not valid
    return (gid_t)-1;
  } // end if

  struct passwd *pwd = getpwnam(username);
  if (pwd == NULL) {
    // user not found
    return (gid_t)-1;
  } // end if

  return pwd->pw_gid;
} // end get_gid_by_username
