//Cosimo Lombardi 2031075 CSAP project 2025/2026
//Simone Di Gregorio Matricola CSAP project 2025/2026

#include <dirent.h>

//check if a directory exists
int check_directory(char *path){
    DIR *d = opendir(path);
    if (d) {
        closedir(d);  // close the directory
        return 1;     // the directory exists
    }
    return 0;
}//end check_directory

//crea una directory
int create_directory(char *directory){
   printf("Under construction\n");
   return 0;
}//end create_directory