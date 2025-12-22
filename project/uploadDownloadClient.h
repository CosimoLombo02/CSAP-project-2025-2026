#include <stdio.h>


char logged_user[64] = "";

// Struct for active uploads
typedef struct ActiveUpload {
    pid_t pid;
    char filename[256];
    struct ActiveUpload *next;
} ActiveUpload;

ActiveUpload *active_uploads = NULL;
char current_prompt[BUFFER_SIZE] = "> ";

void update_prompt(const char *buffer) {
    // Basic heuristic: find last occurrence of "> "
    const char *last_prompt = strrchr(buffer, '>');
    if (last_prompt && *(last_prompt + 1) == ' ') {
        // Need to find the start of the line or just take a reasonable suffix?
        // Server sends: "\n/path > " or just "/path > "
        // We can just copy the whole last line? 
        // Or simplified: just copy the buffer if it looks like a prompt?
        // The buffer might contain multiple lines.
        
        // Let's assume the prompt is at the end of the buffer.
        size_t len = strlen(buffer);
        if (len > 2 && buffer[len-2] == '>' && buffer[len-1] == ' ') {
            // Find start of this line
            const char *start = buffer + len - 1;
            while (start > buffer && *start != '\n') {
                start--;
            }
            if (*start == '\n') start++;
            
            strncpy(current_prompt, start, sizeof(current_prompt) - 1);
            current_prompt[sizeof(current_prompt) - 1] = '\0';
        }
    }
}//end update_prompt

void add_upload(pid_t pid, char *filename) {
    ActiveUpload *new_node = malloc(sizeof(ActiveUpload));
    new_node->pid = pid;
    strncpy(new_node->filename, filename, sizeof(new_node->filename) - 1);
    new_node->filename[sizeof(new_node->filename) - 1] = '\0';
    new_node->next = active_uploads;
    active_uploads = new_node;
}//end add_upload

// Function to remove the upload from the list and print the result
void remove_and_print_upload(pid_t pid, int status) {
    ActiveUpload **curr = &active_uploads;
    while (*curr) {
        if ((*curr)->pid == pid) {
            ActiveUpload *temp = *curr;
            
            if (WIFEXITED(status)) {
                int exit_code = WEXITSTATUS(status);
                if (exit_code == 0) {
                     printf("\nBackground upload of %s completed.\n%s<", temp->filename, current_prompt);
                } else if (exit_code == 101) {
                     printf("\nBackground upload of %s failed: You are not logged in.\n%s<", temp->filename, current_prompt);
                } else if (exit_code == 102) {
                     printf("\nBackground upload of %s failed: File does not exist or permission denied!\n%s<", temp->filename, current_prompt);
                } else if (exit_code == 103) {
                     printf("\nBackground upload of %s failed: Server rejected upload.\n%s<", temp->filename, current_prompt);
                } else {
                     printf("\nBackground upload of %s failed with error code %d.\n%s<", temp->filename, exit_code, current_prompt);
                }
            } else {
                printf("\nBackground upload of %s terminated abnormally.\n%s<", temp->filename, current_prompt);
            }

            fflush(stdout);
            *curr = (*curr)->next;
            free(temp);
            return;
        }
        curr = &(*curr)->next;
    }
}//end remove_and_print_upload

void sigchld_handler(int sig) {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        remove_and_print_upload(pid, status);
    }
}//end sigchld_handler