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
        snprintf(out, out_size, "Errore: impossibile leggere %s: %s\n", fullpath, strerror(errno));
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


//this functions upload a file to the server via socket
int upload_file(int client_sock, char *clientPath, char *serverPath) {

  

}//end upload file
    
