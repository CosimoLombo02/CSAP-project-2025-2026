// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

// AUTO-REFACTORED implementation from utils.h
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

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
  char path[512];

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


// Helper to normalize path logically (resolve . and .. string-wise)
void normalize_path(char *path) {
    char *p = path;
    char *out = path;
    
    // Approach: Use a temporary stack buffer
    char stack[PATH_MAX];
    char *token;
    char temp_path[PATH_MAX];
    strncpy(temp_path, path, PATH_MAX);
    
    int stack_len = 0;
    stack[0] = '\0';
    
    token = strtok(temp_path, "/");
    while(token != NULL) {
        if(strcmp(token, ".") == 0) {
            // ignore
        } else if(strcmp(token, "..") == 0) {
            // pop
            char *last_slash = strrchr(stack, '/');
            if(last_slash) {
                *last_slash = '\0';
            } else {
                 stack[0] = '\0'; // root
            }
        } else {
            // push
            if(stack_len + strlen(token) + 2 < PATH_MAX) {
                strcat(stack, "/");
                strcat(stack, token);
            }
        }
        token = strtok(NULL, "/");
    }
    
    if(strlen(stack) == 0) strcpy(stack, "/");
    
    strcpy(path, stack);
}

// this function resolves and checks a path
// 0 not valid, 1 valid
int resolve_and_check_path(const char *input, const char *loggedCwd, const char *command) {
  char absolute_path[PATH_MAX];
  char path_to_resolve[PATH_MAX];
  char normalized_logical[PATH_MAX];

  char cwd[PATH_MAX];
  if (getcwd(cwd, sizeof(cwd)) == NULL) {
      perror("getcwd failed");
      return 0;
  }

  // Handle "absolute" paths (relative to Server Root)
  if (input[0] == '/') {
      if (snprintf(path_to_resolve, sizeof(path_to_resolve), "%s%s", original_cwd, input) >= (int)sizeof(path_to_resolve)) {
          fprintf(stderr, "Path too long: %s%s\n", original_cwd, input);
          return 0;
      }
  } else {
      // Relative paths: Resolve against CWD
      if (snprintf(path_to_resolve, sizeof(path_to_resolve), "%s/%s", cwd, input) >= (int)sizeof(path_to_resolve)) {
          fprintf(stderr, "Path too long: %s/%s\n", cwd, input);
          return 0;
      }
  }
  
  // Normalize the path
  strncpy(normalized_logical, path_to_resolve, PATH_MAX);
  normalize_path(normalized_logical);

 
  //printf("DEBUG: Resolving: %s -> Normalized: %s\n", path_to_resolve, normalized_logical);

  if((strcmp(command, "create") == 0) || (strcmp(command, "move") == 0)){
      char temp_path[PATH_MAX];
      char *dir_name;
      char resolved_dir[PATH_MAX];

      strncpy(temp_path, normalized_logical, sizeof(temp_path));
      temp_path[sizeof(temp_path) - 1] = '\0';
      
      dir_name = dirname(temp_path);
      
      // Resolve the parent directory
      if (realpath(dir_name, resolved_dir) == NULL) {
           return 0; // Parent directory does not exist
      }

      // Check if the resolved parent directory is inside the sandbox
      size_t root_len = strlen(loggedCwd);
      if (strncmp(resolved_dir, loggedCwd, root_len) != 0 || 
         (resolved_dir[root_len] != '\0' && resolved_dir[root_len] != '/')) { // check if the loggedCwd is contained in the resolved_dir and if the resolved_dir ends with a slash or with terminator
          if(strcmp(normalized_logical, loggedCwd) == 0) {
             return 1;
          }
          return 0; // Parent is outside sandbox
      }

      return 1;

  }else if (strcmp(command, "list") != 0) {

    if (realpath(normalized_logical, absolute_path) == NULL) {
        return 0;
    }

    // check if the path is inside the sandbox
    size_t root_len = strlen(loggedCwd);

    if (strncmp(absolute_path, loggedCwd, root_len) != 0 || 
       (absolute_path[root_len] != '\0' && absolute_path[root_len] != '/')) {
        return 0; // path outside the sandbox
    }

    
  } else {
    
  // resolve the path
    if (realpath(normalized_logical, absolute_path) == NULL) {
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

// Helper function to build the absolute path
void build_abs_path(char *abs_path,
                    const char *loggedCwd,
                    const char *user_path) {

    if (!abs_path || !loggedCwd || !user_path) {
        return;
    } // end if

    // Case 1: absolute path (relative to Server Root)
    if (user_path[0] == '/') {
        if (snprintf(abs_path, PATH_MAX, "%s%s", original_cwd, user_path) >= PATH_MAX) {
             // Truncation handled safely by snprintf but ignored
        }
    }
    // Case 2: relative path (relative to loggedCwd argument)
    else {
        if (snprintf(abs_path, PATH_MAX, "%s/%s", loggedCwd, user_path) >= PATH_MAX) {
             // Truncation handled safely
        }
    } // end else

    // Use logical normalization instead of just removing //
    normalize_path(abs_path);

}// end build_abs_path
