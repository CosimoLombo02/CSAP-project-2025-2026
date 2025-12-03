//Cosimo Lombardi 2031075 CSAP project 2025/2026
//Simone Di Gregorio Matricola CSAP project 2025/2026

#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>




//create a directory
int create_directory(char *directory,mode_t permissions){
   if (directory == NULL || strlen(directory) == 0) {
    perror ("Invalid directory name");
    return 0;
   }

  
   mode_t old_umask = umask(0);
   if (mkdir(directory, permissions) == 0){
    umask(old_umask);  
    return 1;

   }

   //if the directory already exists
   if (errno == EEXIST){
    umask(old_umask);  
    return 1;
   }

   umask(old_umask);  

   perror("Error in the directory creation!");
   return 0;
}//end create_directory