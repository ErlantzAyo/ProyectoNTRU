

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>


void EscribirFichero(char *nombreFichero, char *variable, double dato);
void WriteFileKey(char *nombreFichero, uint8_t* key, size_t len);
void readFileKey(char *nombreFichero, uint8_t* key, size_t len);
