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

// send to the client: "<msg>\n<cwd> > "
void send_with_cwd(int client_sock, const char *msg, char *loggedUser) {
  if (loggedUser[0] == '\0') {
    write(client_sock, msg, strlen(msg));
    return;
  }
    char cwd_buf[PATH_MAX];
    char out[BUFFER_SIZE];

    out[0] = '\0';

    // add the message, if present
    if (msg != NULL && msg[0] != '\0') {
        // add the message + newline
        snprintf(out, sizeof(out), "%s\n", msg);
    }

    // add the cwd + " > "
    if (getcwd(cwd_buf, sizeof(cwd_buf)) != NULL) {
        size_t len = strlen(out);
        snprintf(out + len, sizeof(out) - len, "%s > ", cwd_buf);
    } else {
        size_t len = strlen(out);
        snprintf(out + len, sizeof(out) - len, "> ");
    }

    // just one write
    write(client_sock, out, strlen(out));
}
