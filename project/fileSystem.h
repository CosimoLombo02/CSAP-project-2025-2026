// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

// create a directory
int create_directory(char *directory, mode_t permissions) {
  if (directory == NULL || strlen(directory) == 0) {
    perror("Invalid directory name");
    return 0;
  }

  mode_t old_umask = umask(0);
  if (mkdir(directory, permissions) == 0) {
    umask(old_umask);
    return 1;
  }

  // if the directory already exists
  if (errno == EEXIST) {
    umask(old_umask);
    return 1;
  }

  umask(old_umask);

  perror("Error in the directory creation!");
  return 0;
} // end create_directory

// create a file
int create_file(char *file, mode_t permissions) {
  if (file == NULL || strlen(file) == 0) {
    perror("Invalid file name");
    return 0;
  }

  mode_t old_umask = umask(0);
  if (open(file, O_CREAT | O_EXCL, permissions) >= 0) {
    umask(old_umask);
    return 1;
  }

  // if the file already exists
  if (errno == EEXIST) {
    umask(old_umask);
    return 1;
  }

  umask(old_umask);
  perror("Error in the file creation!");
  return 0;
} // end create_file


//function that change the current directory
//if 1 success else fail
int change_directory(char * path){

  if (chdir(path) != 0) {
        perror("chdir fallito");
        return 0;
    }

    return 1;

}//end change directory

//function that returns the current working directory
void cwd(int client_sock){
  char cwd[1024];
  if(getcwd(cwd, sizeof(cwd)) != NULL){
    //printf("Current working dir: %s\n", cwd);
    write(client_sock, cwd, strlen(cwd));
    write(client_sock, "\n", 1);
  }else{
    write(client_sock, "Error in the cwd function!", strlen("Error in the cwd function!"));
    return ;
  }
}//end fucntion cwd