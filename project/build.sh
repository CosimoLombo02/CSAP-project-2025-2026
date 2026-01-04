#!/bin/bash

clear 

set -e

rm -f client server

# CLIENT
gcc -Wextra -Iinclude \
  src/client.c src/clientFunctions.c src/uploadDownloadClient.c src/utils.c \
  -o client

# SERVER
gcc -Wextra -Iinclude \
  src/server.c src/serverFunctions.c src/utils.c src/fileSystem.c src/signalHandlersServer.c src/lockServer.c src/clientsHandler.c \
  -o server

echo "Build completed successfully"