//Cosimo Lombardi 2031075 CSAP project 2025/2026
//Simone Di Gregorio Matricola CSAP project 2025/2026

#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

//check if a directory exists
int check_directory(char *path){
    DIR *d = opendir(path);
    if (d) {
        closedir(d);  // close the directory
        return 1;     // the directory exists
    }
    return 0;
}//end check_directory

//create a directory
int create_directory(char *directory){
   if (directory == NULL || strlen(directory) == 0) {
    perror ("Invalid directory name");
    return 0;
   }

   //create the directory with rwx permissions for the owner and group
   //the first 0 is for the octal number
   if (mkdir(directory, 0770) == 0){
    return 1;
   }

   //if the directory already exists
   if (errno == EEXIST){
    return 1;
   }

   perror("Error in the directory creation!");
   return 0;
}//end create_directory