// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

#include <dirent.h>
#include <grp.h>
#include <pwd.h>

// global variables
extern char original_cwd[PATH_MAX];

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

  // copies "./" in the path
  strcpy(path, "./");

  // appends the username to the path
  strncat(path, username, sizeof(path) - strlen(path) - 1);

  // now path = "./username"
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

// this function removes the prefix from a string
char *remove_prefix(const char *str, const char *prefix) {
    size_t len_prefix = strlen(prefix);

    // prefix must be the start of str
    if (strncmp(str, prefix, len_prefix) == 0) {

        // If there is a slash immediately after the prefix, we skip it
        if (str[len_prefix] == '/')
            return (char *)(str + len_prefix); 

        return (char *)(str + len_prefix); 
    }

    // if there is no prefix, return the string as it is
    return (char *)str;
} // end remove_prefix


// this function resolves and checks a path
// 0 not valid, 1 valid
int resolve_and_check_path(const char *input, const char *loggedCwd, const char *command) {
  char absolute_path[PATH_MAX];

  if (strcmp(command, "list") != 0) {

    // resolve the path
    if (realpath(input, absolute_path) == NULL) {
        return 0;
    }

    //debug
    printf("Path resolved: %s\n", absolute_path);
    printf("Logged CWD: %s\n", loggedCwd);
    printf("Input: %s\n", input);

    // check if the path is inside the sandbox
    size_t root_len = strlen(loggedCwd);

    if (strncmp(absolute_path, loggedCwd, root_len) != 0) {
        return 0; // path outside the sandbox
    }

    
  } else {
    
  // resolve the path
    if (realpath(input, absolute_path) == NULL) {
        return 0;
    }

    // check if the path is inside the sandbox
    size_t root_len = strlen(original_cwd);

    if (strncmp(absolute_path, original_cwd, root_len) != 0) {
        return 0; // path outside the sandbox
    }
  }//end else
  return 1;
    
} // end resolve_and_check_path

