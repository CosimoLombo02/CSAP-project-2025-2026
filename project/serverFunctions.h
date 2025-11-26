//Cosimo Lombardi 2031075 CSAP project 2025/2026
//Simone Di Gregorio Matricola CSAP project 2025/2026

#define BUFFER_SIZE 1024 //buffer size for the messages

/*This function is a kind of login, if the username exits
in the file users.txt it sends a success message to the client, otherwise 
it sends a failure message */
void login(char *username,int client_sock){

    FILE *f = fopen("users.txt", "r");
    if(f == NULL){
        perror("Error in the file opening!");
        exit(1);
    }//end if 

    char line[BUFFER_SIZE];
    while(fgets(line, BUFFER_SIZE, f) != NULL){

        //line[strcspn(line, "\n")] = '\0'; //remove the newline character
line[strcspn(line, "\r\n")] = '\0'; // rimuove newline

        if(strcmp(line, username) == 0){
             write(client_sock, "Login successful!\n", strlen("Login successful!\n")); //send the message to the client
             fclose(f); 
            return;
        }//end if 
        
    }//end while

    //If I am here the username does not exist
    write(client_sock, "Login failed!\n", strlen("Login failed!\n")); //send the message to the client
 
fclose(f); 
return ; 

}//end function login
    
/*This function is a the main function that handles the client,
as we can see it has different behaviuors based on the message received  */
void handle_client(int client_sock){

    char buffer[BUFFER_SIZE];
    int n;

    
    while((n = read(client_sock, buffer, BUFFER_SIZE-1)) > 0){
        buffer[n] = '\0'; /*Terminates the buffer, maybe we can consider this as a 
        buffer overflow security measure ?
        */
        printf("Client: %s", buffer); //print the message received from the client, server side
       // write(client_sock, buffer, n); //send the message to the client 

    
      

       
        //look for login in the buffer
        if(strstr(buffer, "login") != NULL){
            char *cmd = strtok(buffer, " ");   // first token is login
            char *usr = strtok(NULL, " ");     // second token is the username

            
           
           if(usr != NULL){
            usr[strcspn(usr, "\n")] = '\0'; //remove the newline character
            login(usr, client_sock);

           }
            
        }//end if
        

    }//end while

    close(client_sock);
    printf("Client disconnected\n"); //Debug 
    exit(0); // ends the child process

}//end function client handler

// Ignores the SIGCHLD signal to avoid zombies
void sigchld_handler(int s) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}//end function sigchld_handler

//do not know if it works properly, this function is over testing 
int handle_exit(char *buffer){

    if(strcmp(buffer, "exit\n") == 0){
        return 1;
    }//end if 
    return 0;
}
