
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

#include "file_io.h"
#include "utils.h"

void EscribirFichero(char *nombreFichero, char *variable, double dato) {
  FILE *fp;
  fp = fopen(nombreFichero, "a");

  if (fp == NULL) {
    printf("Error!");
    exit(1);
  }

  fprintf(fp, "%s %f\n", variable, dato);
  fclose(fp);
}
double readFileDouble(char *nombreFichero) {
  FILE *fp;
double dato;
  fp = fopen(nombreFichero, "r");

  if (fp == NULL) {
    printf("Error! NO existe el archivo %s", nombreFichero);
    exit(1);
  }
  fscanf(fp, "%lf",&dato);
  printf("\nDATO = %f",dato);
  return dato;
  fclose(fp);
}
void WriteFileKey(char *nombreFichero, uint8_t* key, size_t len) {
  FILE *fp;
  fp = fopen(nombreFichero, "w");

  if (fp == NULL) {
    printf("Error!");
    exit(1);
  }
  fwrite(key, 1,len,fp);
  fclose(fp);
}
void readFileKey(char *nombreFichero, uint8_t* key, size_t len) {
  FILE *fp;
  fp = fopen(nombreFichero, "r");

  if (fp == NULL) {
    printf("Error! NO existe el archivo %s", nombreFichero);
    exit(1);
  }
  fread(key, 1,len,fp);
  printBstr("KEY IN FILE:", key, len);
  fclose(fp);
}
