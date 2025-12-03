//Cosimo Lombardi 2031075 CSAP project 2025/2026
//Simone Di Gregorio Matricola CSAP project 2025/2026




#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include "clientFunctions.h"





int main(int argc, char *argv[]){

    //default values
    char *server_ip = "127.0.0.1";
    int port = 8080;

    //params are mandatory
    if(argc != 3){
        printf("Needs params!");
        exit(1);
    }

    //overwrite if passed as parameters
    if (argc >= 2) server_ip = argv[1];
    if (argc >= 3) port = atoi(argv[2]);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0){
        perror("Error in the socket creation!");
        return 1; //exit 
    }//end if 
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if(inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0){
        perror("Invalid address/ Address not supported");
        return 1; //exit 
    }//end if 

    if(connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
        perror("Connection failed");
        return 1; //exit 
    }//end if 
    
    //If I am here the connection is working correctly
    printf("Connected to server at %s:%d\n", server_ip, port);
   
        



    char buffer[BUFFER_SIZE];
    
    while(1){
        printf("<");
        if(fgets(buffer, BUFFER_SIZE, stdin) == NULL) break;

        /*if the user types exit the client terminates, 
        but this is just a prototype, we have to handle the 
        -b option as the professor wrote on the slides 
        */
        if(strcmp(buffer,"exit\n") == 0){
            printf("Bye!\n"); //output on the console
            break;
        }//end if 

        


        

        //send to the server 
        if(write(sock, buffer, strlen(buffer)) < 0){
            perror("Error in the write!");
            break;
        }//end if 
            
        //receive from the server 
        int n = read(sock, buffer, BUFFER_SIZE-1);
        if (n < 0){
            perror("Error in the read!");
            break;
        }//end if 
        else{
            if(n==0){
                printf("Server disconnected\n"); 
               break; //the client terminates
             }//end if 
        }//end else
        buffer[n] = '\0'; //string terminator
        printf("%s", buffer); //Debug 
    
        
    }//end while
    
    close(sock); //closes the socket
    return 0;
    
    
}//end main