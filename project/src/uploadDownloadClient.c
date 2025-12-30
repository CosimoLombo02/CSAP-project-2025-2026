#include "uploadDownloadClient.h"
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


char logged_user[64] = "";
ActiveOperation *active_operations = NULL;
char current_prompt[BUFFER_SIZE] = "> ";

void update_prompt(const char *buffer) {
    // Basic heuristic: find last occurrence of "> "
    const char *last_prompt = strrchr(buffer, '>');
    if (last_prompt && *(last_prompt + 1) == ' ') {
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

void add_operation(pid_t pid, OperationType type, char *server_path, char *client_path) {
    ActiveOperation *new_node = malloc(sizeof(ActiveOperation));
    new_node->pid = pid;
    new_node->type = type;
    strncpy(new_node->server_path, server_path, sizeof(new_node->server_path) - 1);
    new_node->server_path[sizeof(new_node->server_path) - 1] = '\0';
    
    strncpy(new_node->client_path, client_path, sizeof(new_node->client_path) - 1);
    new_node->client_path[sizeof(new_node->client_path) - 1] = '\0';
    
    new_node->next = active_operations;
    active_operations = new_node;
}//end add_operation

// Function to remove the operation from the list and print the result
void remove_and_print_operation(pid_t pid, int status) {
    ActiveOperation **curr = &active_operations;
    while (*curr) {
        if ((*curr)->pid == pid) {
            ActiveOperation *temp = *curr;
            
            if (WIFEXITED(status)) {
                int exit_code = WEXITSTATUS(status);
                
                if (temp->type == OP_UPLOAD) {
                    if (exit_code == 0) {
                        printf("\n[Background] Command: upload %s %s concluded.\n%s", temp->server_path, temp->client_path, current_prompt);
                    } else if (exit_code == 101) {
                         printf("\n[Background] Command: upload %s %s failed: You are not logged in.\n%s", temp->server_path, temp->client_path, current_prompt);
                    } else if (exit_code == 102) {
                         printf("\n[Background] Command: upload %s %s failed: File does not exist or permission denied!\n%s", temp->server_path, temp->client_path, current_prompt);
                    } else if (exit_code == 103) {
                         printf("\n[Background] Command: upload %s %s failed: Server rejected upload.\n%s", temp->server_path, temp->client_path, current_prompt);
                    } else {
                         printf("\n[Background] Command: upload %s %s failed with error code %d.\n%s", temp->server_path, temp->client_path, exit_code, current_prompt);
                    }
                } else if (temp->type == OP_DOWNLOAD) {
                    if (exit_code == 0) {
                        printf("\n[Background] Command: download %s %s concluded\n%s", temp->server_path, temp->client_path, current_prompt);
                    } else if (exit_code == 101) {
                        printf("\n[Background] Command: download %s %s failed (Not logged in)\n%s", temp->server_path, temp->client_path, current_prompt);
                    } else if (exit_code == 102) {
                        printf("\n[Background] Command: download %s %s failed (File not found)\n%s", temp->server_path, temp->client_path, current_prompt);
                    } else if (exit_code == 103) {
                        printf("\n[Background] Command: download %s %s failed (Client write error)\n%s", temp->server_path, temp->client_path, current_prompt);
                    } else {
                        printf("\n[Background] Command: download %s %s failed (Code %d)\n%s", temp->server_path, temp->client_path, exit_code, current_prompt);
                    }
                }
            } else {
                printf("\n[Background] operation terminated abnormally.\n%s", current_prompt);
            }

            fflush(stdout);
            *curr = temp->next;
            free(temp);
            return;
        }
        curr = &(*curr)->next;
    }
}//end remove_and_print_operation

void sigchld_handler(int sig) {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        remove_and_print_operation(pid, status);
    }
}//end sigchld_handler
