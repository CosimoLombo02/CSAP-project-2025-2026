//Cosimo Lombardi 2031075 CSAP project 2025/2026
//Simone Di Gregorio Matricola CSAP project 2025/2026

//this functions checks if the username exists
//0 not exists, 1 exists
int check_username(char* username){

    //just to be sure
    if(username == NULL || strlen(username) == 0){
        return 0;
    }//end if 

    FILE *f = fopen("users.txt", "r");
    if(f == NULL){
        perror("Error in the file opening!");
       // exit(1);
       return 0;
    }//end if 

    char line[BUFFER_SIZE];
    while(fgets(line, BUFFER_SIZE, f) != NULL){

        line[strcspn(line, "\n")] = '\0'; //remove the newline character
      //  line[strcspn(line, "\r\n")] = '\0'; // rimuove newline

        if(strcmp(line, username) == 0){
             
             fclose(f); 
            return 1;
        }//end if 
        
    }//end while

    
 
fclose(f); 
return 0; 

}//end check_username


//this functions checks if the permissions are valid
//0 not valid , 1 valid

int check_permissions(char *permissions){
    if(permissions[0]>='0' && permissions[0] <= '7'){
        if(permissions[1]>='0' && permissions[1] <= '7'){
            if(permissions[2]>='0' && permissions[2] <= '7'){
                return 1;
            }//end if 
        }//end if 
    }//end if 


    return 0;

}//end check permissions


