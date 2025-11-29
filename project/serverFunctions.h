//Cosimo Lombardi 2031075 CSAP project 2025/2026
//Simone Di Gregorio Matricola CSAP project 2025/2026

#define BUFFER_SIZE 1024 //buffer size for the messages

/*This function is a kind of login, if the username exits
in the file users.txt it sends a success message to the client, otherwise 
it sends a failure message */
void login(char *username,int client_sock){

    //check if the username is null or made only by spaces
    if(username == NULL || strlen(username) == 0){
        write(client_sock, "Insert Username!\n", strlen("Insert Username!\n")); //send the message to the client
        return;
    }//end if 

    FILE *f = fopen("users.txt", "r");
    if(f == NULL){
        perror("Error in the file opening!");
        exit(1);
    }//end if 

    char line[BUFFER_SIZE];
    while(fgets(line, BUFFER_SIZE, f) != NULL){

        line[strcspn(line, "\n")] = '\0'; //remove the newline character
      //  line[strcspn(line, "\r\n")] = '\0'; // rimuove newline

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

          
      

        //test
        char *firstToken = strtok(buffer," "); //first token is the command 
        char *secondToken = strtok(NULL," "); //second token of the command
        char *thirdToken = strtok(NULL," "); //third token of the command

        //removes eventually \n
        if (firstToken != NULL) {
            firstToken[strcspn(firstToken, "\n")] = '\0';
        }
        if (secondToken != NULL) {
            secondToken[strcspn(secondToken, "\n")] = '\0';
        }
        if (thirdToken != NULL) {
            thirdToken[strcspn(thirdToken, "\n")] = '\0';
        }

      
       
      // printf("%d\n",strcmp(firstToken,"login")); //Debug 

             if(strcmp("login",firstToken)==0){
                     
                   
                    login(secondToken,client_sock);

        
             }else{
                if(strcmp("create_user",firstToken)==0){
                //test for create user
                write(client_sock,"test create ok!\n",strlen("test create ok!\n"));
                }else{
                //if i am here, the user input is invalid
                write(client_sock,"Invalid Command2!\n",strlen("Invalid Command2!\n"));
                }//end nested else

             }//end else


      
       

        

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
