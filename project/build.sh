#!/bin/bash


clear

# Rimuovo i vecchi eseguibili
rm -f client
rm -f server

# Compilo i nuovi
gcc client.c -o client
gcc server.c -o server

echo "Compilazione completata!"
