// Cosimo Lombardi 2031075 CSAP project 2025/2026
// Simone Di Gregorio 2259275 CSAP project 2025/2026

// AUTO-REFACTORED: split header/implementation for modularity
#ifndef UTILS_H
#define UTILS_H

#include <dirent.h>
#include <grp.h>
#include <pwd.h>
#include <libgen.h>
#include <fcntl.h>

// global variables
extern char original_cwd[PATH_MAX];

// this functions checks if the permissions are valid
// 0 not valid , 1 valid

int check_permissions(char *permissions);
int check_directory(char *path);
int check_username(char *username);
char *get_group();
uid_t get_uid_by_username(char *username);
gid_t get_gid_by_username(char *username);
char *remove_prefix(const char *str, const char *prefix);
int resolve_and_check_path(const char *input, const char *loggedCwd, const char *command);
void build_abs_path(char *abs_path, const char *loggedCwd, const char *user_path);

#endif // UTILS_H