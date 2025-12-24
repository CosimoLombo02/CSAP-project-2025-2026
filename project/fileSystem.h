// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include <pwd.h> 
#include <grp.h> 
#include <sys/file.h> 

extern char start_cwd[PATH_MAX];

// lock the file with shared lock
int lock_shared_fd(int fd) {
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type   = F_RDLCK;   // shared
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;         // whole file

    while (fcntl(fd, F_SETLK, &fl) == -1) {
        if (errno == EINTR) continue;
        return -1;
    } // end while
    return 0;
} // end lock_shared_fd

// lock the file with exclusive lock
int lock_exclusive_fd(int fd) {
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type   = F_WRLCK;   // exclusive
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;

    while (fcntl(fd, F_SETLK, &fl) == -1) {
        if (errno == EINTR) continue;
        return -1;
    } // end while
    return 0;
} // end lock_exclusive_fd

// unlock the file
int unlock_fd(int fd) {
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type   = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;

    while (fcntl(fd, F_SETLKW, &fl) == -1) {
        if (errno == EINTR) continue;
        return -1;
    } // end while
    return 0;
} // end unlock_fd

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
        perror("chdir failed");
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

        char *pos = strstr(cwd_buf, start_cwd);

    if (pos != NULL) {
        memmove(
            pos,
            pos + strlen(start_cwd),
            strlen(pos + strlen(start_cwd)) + 1
        );
    }

        snprintf(out + len, sizeof(out) - len, "%s > ", pos);
    } else {
        size_t len = strlen(out);
        snprintf(out + len, sizeof(out) - len, "> ");
    }

    // just one write
    write(client_sock, out, strlen(out));
}//end send cwd

// converts permissions to rwxr-xr-x
void format_permissions(mode_t mode, char *perms) {
    strcpy(perms, "----------");
    
    if (S_ISDIR(mode)) perms[0] = 'd';
    if (S_ISLNK(mode)) perms[0] = 'l'; // for symbolic links
    
    // Proprietario
    if (mode & S_IRUSR) perms[1] = 'r';
    if (mode & S_IWUSR) perms[2] = 'w';
    if (mode & S_IXUSR) perms[3] = 'x';
    
    // Gruppo
    if (mode & S_IRGRP) perms[4] = 'r';
    if (mode & S_IWGRP) perms[5] = 'w';
    if (mode & S_IXGRP) perms[6] = 'x';
    
    // Altri
    if (mode & S_IROTH) perms[7] = 'r';
    if (mode & S_IWOTH) perms[8] = 'w';
    if (mode & S_IXOTH) perms[9] = 'x';
}//end format permissions

// returns a string with info of a single file (now complete in style ls -l)
void file_info_string(const char *fullpath, char *out, size_t out_size) {
    struct stat file_stat;
    char perms[11];
    char time_str[80];
    
    // Important: we use lstat to not follow symbolic links <<<
    if (lstat(fullpath, &file_stat) == -1) { 
        snprintf(out, out_size, "Error: impossible to read %s: %s\n", fullpath, strerror(errno));
        return;
    }

    format_permissions(file_stat.st_mode, perms);

    //users and groups
    struct passwd *pw = getpwuid(file_stat.st_uid);
    struct group *gr = getgrgid(file_stat.st_gid);
    
    const char *username = pw ? pw->pw_name : "unknown";
    const char *groupname = gr ? gr->gr_name : "unknown";

    // formats the date: es. "Dec 10 10:59"
    strftime(time_str, sizeof(time_str), "%b %e %H:%M", localtime(&file_stat.st_mtime));

    // prints the file info
    // Format: Permissions Links User Group Size Date FileName
    int written = snprintf(out, out_size, 
             "%s %2lu %s %s %10lld %s %s", 
             perms, 
             (unsigned long)file_stat.st_nlink, 
             username,
             groupname,
             (long long)file_stat.st_size, 
             time_str,
             strrchr(fullpath, '/') ? strrchr(fullpath, '/') + 1 : fullpath);
    
    // handles symbolic links (adds " -> target")
    if (S_ISLNK(file_stat.st_mode) && written > 0) {
        char link_target[PATH_MAX];
        ssize_t len = readlink(fullpath, link_target, sizeof(link_target) - 1);
        
        if (len != -1) {
            link_target[len] = '\0';
            // adds the link target
            size_t current_len = strlen(out);
            written += snprintf(out + current_len, out_size - current_len, " -> %s", link_target);
        }
    }
    
    // adds a newline and null terminator
    if (written < out_size) {
        out[written] = '\n';
        out[written + 1] = '\0';
    } else if (out_size > 0) {
        
        //if the buffer is full, ensure termination and newline
        out[out_size - 2] = '\n';
        out[out_size - 1] = '\0';
    }
}

// Returns a string with all the info of the directory
void list_directory_string(const char *path, char *out, size_t out_size) {
    DIR *dir;
    struct dirent *entry;
    char fullpath[PATH_MAX]; 
    char filebuf[1024]; 
    
    char *current_pos = out;
    size_t remaining_size = out_size;
    ssize_t written;

    if (out_size == 0) return;
    *current_pos = '\0'; 

    if ((dir = opendir(path)) == NULL) {
        snprintf(out, out_size, "Errore: impossibile aprire %s: %s\n", path, strerror(errno));
        return;
    }

    //add header
    written = snprintf(current_pos, remaining_size, "--- Content of: %s ---\n", path);
    if (written > 0) {
        current_pos += written;
        remaining_size -= written;
    }

    // loops and appends files
    while ((entry = readdir(dir)) != NULL && remaining_size > 0) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
        file_info_string(fullpath, filebuf, sizeof(filebuf));
        
        // appends files info to the output string
        size_t filebuf_len = strlen(filebuf);
        if (filebuf_len >= remaining_size) {
            filebuf_len = remaining_size - 1; 
        }

        if (filebuf_len > 0) {
            memcpy(current_pos, filebuf, filebuf_len);
            current_pos += filebuf_len;
            remaining_size -= filebuf_len;
            *current_pos = '\0'; // keeps the string terminated
        } else if (remaining_size <= 1) {
            break; // runs out of space
        }
    }

    closedir(dir);
}//end list directory string


void handle_upload(int client_sock, char *server_path, char* client_path, char *loggedUser, uid_t uid, gid_t gid) {
  
  char final_path[PATH_MAX];
  struct stat info;

  // Check if server_path is a directory
  if (stat(server_path, &info) == 0 && S_ISDIR(info.st_mode)) {
      // It's a directory, append client filename
      snprintf(final_path, sizeof(final_path), "%s/%s", server_path, basename(client_path));
  } else {
      // It's a file path (new or existing), use as is
      strncpy(final_path, server_path, sizeof(final_path));
      final_path[sizeof(final_path) - 1] = '\0';
  }

  // sends READY
  char ready_msg[PATH_MAX + 32];
  snprintf(ready_msg, sizeof(ready_msg), "%s READY!\n", client_path);
  send(client_sock, ready_msg, strlen(ready_msg), 0);

  char response[16] = {0};
  if (recv(client_sock, response, sizeof(response) - 1, 0) <= 0) {
    return;
  }

  if (strcmp(response, "OK\n") != 0) {
    send_with_cwd(client_sock, "File not found or permission denied!\n", loggedUser);
    return;
  }

  uint64_t net_size;
  if (recv(client_sock, &net_size, sizeof(net_size), MSG_WAITALL) != sizeof(net_size)) {
    return;
  }

  // opens the file in write mode
  FILE *fd = fopen(final_path, "wb");
  if (!fd) {
    send_with_cwd(client_sock, "Error opening server file\n", loggedUser);
    return;
  }

  // Lock the file (Exclusive)
  if (lock_exclusive_fd(fileno(fd)) < 0) {
      perror("lock_exclusive_fd");
      send_with_cwd(client_sock, "Error locking file\n", loggedUser);
      fclose(fd);
      return;
  }

  uint64_t file_size = be64toh(net_size);

  char buffer[BUFFER_SIZE];
  uint64_t bytes_received = 0;

  while (bytes_received < file_size) {
    size_t to_read = BUFFER_SIZE;
    if (to_read > (size_t)(file_size - bytes_received)) to_read = (size_t)(file_size - bytes_received);

    ssize_t n = recv(client_sock, buffer, to_read, 0);
    if (n <= 0) { unlock_fd(fileno(fd)); fclose(fd); return; }

    fwrite(buffer, 1, (size_t)n, fd);
    bytes_received += (uint64_t)n;
  }

  
  
  unlock_fd(fileno(fd));
  fclose(fd);

  // here we change the owner of the file
  if (chown(final_path, uid, gid) == -1) {
    send_with_cwd(client_sock, "Error changing file owner\n", loggedUser);
    return;
  }

  send_with_cwd(client_sock, "OK\n", loggedUser);
}//end handle upload

void handle_download(int client_sock, char *server_path, char *loggedUser) {
    if (access(server_path, R_OK) != 0) {
        send_with_cwd(client_sock, "File not found or permission denied\n", loggedUser);
        return;
    }

    struct stat st;
    if (stat(server_path, &st) < 0 || !S_ISREG(st.st_mode)) {
        send_with_cwd(client_sock, "Invalid file\n", loggedUser);
        return;
    }

    // Open and Lock BEFORE sending READY to ensure we can read
    int fd = open(server_path, O_RDONLY);
    if (fd < 0) {
        send_with_cwd(client_sock, "Error opening server file\n", loggedUser);
        return;
    }

    // Lock the file (Shared)
    if (lock_shared_fd(fd) < 0) {
        perror("lock_shared_fd");
        send_with_cwd(client_sock, "Error locking file\n", loggedUser);
        close(fd);
        return;
    }

    // Send READY!
    char ready_msg[64];
    snprintf(ready_msg, sizeof(ready_msg), "READY!\n");
    send(client_sock, ready_msg, strlen(ready_msg), 0);

    // Wait for client OK
    char response[16] = {0};
    if (recv(client_sock, response, sizeof(response) - 1, 0) <= 0) {
        unlock_fd(fd);
        close(fd);
        return;
    }

    if (strncmp(response, "OK", 2) != 0) {
        unlock_fd(fd);
        close(fd);
        send_with_cwd(client_sock, "Error downloading file\n", loggedUser);
        return; // if response is not OK sends error to client and returns
    }

    uint64_t file_size = st.st_size;
    uint64_t net_size = htobe64(file_size);
    
    // Send size
    if (send(client_sock, &net_size, sizeof(net_size), 0) < 0) {
        perror("send size");
        unlock_fd(fd);
        close(fd);
        return;
    }

    // Send file content (fd is already open and locked)
    char buffer[BUFFER_SIZE];
    ssize_t n;
    while ((n = read(fd, buffer, BUFFER_SIZE)) > 0) {
        if (send(client_sock, buffer, n, 0) < 0) {
            perror("send file");
            break;
        }
    }
    
    unlock_fd(fd);
    close(fd);

    // Send final prompt (empty message triggers prompt update in client)
    send_with_cwd(client_sock, "", loggedUser); 
}//end handle download



//this fucntions changes the permissions of a file
int handle_chmod(char *server_path, char *permissions) {
    mode_t mode = strtol(permissions, NULL, 8);

    // 1. Open the file 
    // We use O_RDONLY. flock() works on read-only descriptors on Linux.
    // fcntl(F_WRLCK) would require O_WRONLY which might fail if file is read-only.
    int fd = open(server_path, O_RDONLY);
    if (fd == -1) {
        perror("open failed in handle_chmod");
        return -1;
    }

    // 2. Acquire Exclusive Lock
    // LOCK_EX = Exclusive lock
    if (flock(fd, LOCK_EX) == -1) {
        perror("flock failed");
        close(fd);
        return -1;
    }

    // 3. Change permissions
    int result = fchmod(fd, mode);
    if (result == -1) {
        perror("fchmod failed");
    }

    // 4. Release Lock (Explicitly)
    // LOCK_UN = Unlock
    flock(fd, LOCK_UN); //yes its paranoic but it works!

    // Close file
    close(fd);
    
    return result;
}//end handle_chmod

//this functions move a file from the old path to the new path
//just a prototype without locks
int handle_mv(const char *old_abs, const char *new_abs) {
  struct stat st;
  char full_new_path[PATH_MAX];
  const char *dest_path = new_abs;

  // Check if new_abs is a directory
  if (stat(new_abs, &st) == 0 && S_ISDIR(st.st_mode)) {
    char old_copy[PATH_MAX];
    strncpy(old_copy, old_abs, PATH_MAX);
    old_copy[PATH_MAX - 1] = '\0';
    
    char *filename = basename(old_copy);
    
    snprintf(full_new_path, sizeof(full_new_path), "%s/%s", new_abs, filename);
    dest_path = full_new_path;
  }

  if (rename(old_abs, dest_path) == -1){
    perror("error");
    return -1;
  }
  return 0;
}//end handle_mv

//this functions delete a file
//just a prototype without locks
int handle_delete(char *server_path) {
    // 1. Open the file to lock it
    int fd = open(server_path, O_WRONLY);
    if (fd < 0) {
        // if the file doesn't exist, we just unlink it
        return unlink(server_path);
    }

    // 2. Lock Exclusive (to ensure no one is reading/writing)
    if (lock_exclusive_fd(fd) < 0) {
        perror("lock_exclusive_fd delete");
        close(fd);
        return -1; // Locked by someone else
    }

    // 3. Unlink
    int res = unlink(server_path);

    // 4. Unlock and close
    unlock_fd(fd);
    close(fd);
    
    return res;
}//end handle_delete

//this function handles the read command
void handle_read(int client_sock, char *server_path, char *loggedUser, long offset) {
    int fd = -1;
    int locked = 0;
    
    // Check access
    if (access(server_path, R_OK) != 0) {
        send_with_cwd(client_sock, "File not found or permission denied\n", loggedUser);
        return;
    }

    struct stat st;
    if (stat(server_path, &st) < 0 || !S_ISREG(st.st_mode)) {
        send_with_cwd(client_sock, "Invalid file\n", loggedUser);
        return;
    }

    fd = open(server_path, O_RDONLY);
    if (fd < 0) {
        send_with_cwd(client_sock, "Error opening file\n", loggedUser);
        return;
    }

    // Lock the file
    if (lock_shared_fd(fd) < 0) {
        perror("lock_shared_fd");
        send_with_cwd(client_sock, "Error locking file\n", loggedUser);
        goto release;
    } // end lock_shared_fd
    locked = 1;

    // Get file size, check if it is a regular file
    if (fstat(fd, &st) < 0) {
        send_with_cwd(client_sock, "Invalid file\n", loggedUser);
        goto release;
    } // end fstat

    // Handle offset
    if (offset < 0) offset = 0;
    if (offset > st.st_size) offset = st.st_size;

    if (lseek(fd, offset, SEEK_SET) < 0) {
         send_with_cwd(client_sock, "Error seeking file\n", loggedUser);
         goto release;
    }

    // Send READY!
    char ready_msg[64];
    snprintf(ready_msg, sizeof(ready_msg), "READY!\n");
    if (send(client_sock, ready_msg, strlen(ready_msg), 0) < 0) {
        perror("send ready");
        goto release;
    }

    // Wait for client OK
    char response[16] = {0};
    if (recv(client_sock, response, sizeof(response) - 1, 0) <= 0) {
        goto release; 
    }

    if (strncmp(response, "OK", 2) != 0) {
        goto release; 
    }

    uint64_t bytes_to_send = st.st_size - offset;
    uint64_t net_size = htobe64(bytes_to_send);
    
    // Send size
    if (send(client_sock, &net_size, sizeof(net_size), 0) < 0) {
        perror("send size");
        goto release;
    }

    // Send file content
    char buffer[BUFFER_SIZE];
    ssize_t n;
    uint64_t sent = 0;
    while (sent < bytes_to_send && (n = read(fd, buffer, sizeof(buffer))) > 0) {
        
        if (send(client_sock, buffer, n, 0) < 0) {
            perror("send file");
            break;
        }
        sent += n;
    }

    // Send final prompt
    send_with_cwd(client_sock, "", loggedUser); 

    release:
    if (locked) {
        if (unlock_fd(fd) < 0) {
            perror("unlock_fd");
        }
    } // end unlock_fd
    if (fd >= 0) close(fd);
    return;
}//end handle_read

//this function handles the write command
void handle_write(int client_sock, char *server_path, char *loggedUser, long offset) {
    int fd = -1;
    int locked = 0;
    
    // Check if file exists to determine flags
    if (access(server_path, F_OK) != 0) {
        // Create new
        fd = open(server_path, O_WRONLY | O_CREAT, 0700);
    } else {
        // Open existing without truncation (for patching)
        fd = open(server_path, O_WRONLY);
    }

    if (fd < 0) {
        send_with_cwd(client_sock, "Error opening/creating file\n", loggedUser);
        return;
    }

    // Lock the file with exclusive lock
    if (lock_exclusive_fd(fd) < 0) {
        perror("lock_exclusive_fd");
        send_with_cwd(client_sock, "Error locking file\n", loggedUser);
        goto release;
    } // end lock_exclusive_fd
    locked = 1;

    if (offset > 0) {
        if (lseek(fd, offset, SEEK_SET) < 0) {
             send_with_cwd(client_sock, "Error seeking file\n", loggedUser);
             goto release;
        }
    }

    // Send READY!
    char ready_msg[64];
    snprintf(ready_msg, sizeof(ready_msg), "READY!\n");
    if (send(client_sock, ready_msg, strlen(ready_msg), 0) < 0) {
        perror("send ready");
        goto release;
    }

    // Wait for client OK
    char response[16] = {0};
    if (recv(client_sock, response, sizeof(response) - 1, 0) <= 0) {
        goto release;
    }

    if (strncmp(response, "OK", 2) != 0) {
        goto release; 
    }

    // Receive size
    uint64_t net_size;
    if (recv(client_sock, &net_size, sizeof(net_size), MSG_WAITALL) != sizeof(net_size)) {
        goto release;
    }
    uint64_t file_size = be64toh(net_size);

    // Receive content
    char buffer[BUFFER_SIZE];
    uint64_t bytes_received = 0;
    while (bytes_received < file_size) {
        size_t to_read = BUFFER_SIZE;
        if (to_read > (size_t)(file_size - bytes_received)) to_read = (size_t)(file_size - bytes_received);

        ssize_t n = recv(client_sock, buffer, to_read, 0);
        if (n <= 0) {
            goto release;
        }
        
        if (write(fd, buffer, n) != n) {
            // write not completed
            break;
        } // end if write check
        bytes_received += (uint64_t)n;
    } // end while

    send_with_cwd(client_sock, "Write successful!\n", loggedUser);

    release:
    if (locked) {
        if (unlock_fd(fd) < 0) {
            perror("unlock_fd");
        }
    } // end unlock_fd
    if (fd >= 0) close(fd);
    return;
}//end handle_write



    
