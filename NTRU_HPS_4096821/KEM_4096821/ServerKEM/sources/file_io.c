
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "file_io.h"
#include "utils.h"
#include "transform.h"

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
  //printf("\nDATO = %f",dato);
  return dato;
  fclose(fp);
}
void WriteFileKey(char *nombreFichero, uint8_t* key, size_t len) {
  FILE *fp;
  size_t outl;
  fp = fopen(nombreFichero, "w");

  if (fp == NULL) {
    printf("Error!");
    exit(1);
  }
  //transform uint8_t to base64
  char *out = base64_encode(key,len,&outl);
  fwrite(out, 1,outl,fp);
  fclose(fp);
}
void readFileKey(char *nombreFichero, uint8_t* key, size_t len) {
  FILE *fp;
  fp = fopen(nombreFichero, "r");
  size_t numbytes;
  char *keyb;


  if (fp == NULL) {
    printf("Error! NO existe el archivo %s", nombreFichero);
    exit(1);
  }
    /* Get the number of bytes */
  fseek(fp, 0L, SEEK_END);
  numbytes = ftell(fp);

  /* reset the file position indicator to
the beginning of the file */
fseek(fp, 0L, SEEK_SET);

keyb = malloc(numbytes);

fread(keyb,sizeof(char), numbytes,fp);
//printf("(%s)\n",keyb);
    //tranform base64 to uint8_t
memcpy(key,base64_decode(keyb,numbytes,&len),len);
//key = base64_decode(keyb,numbytes,&len);
//printBstr("KEY read = ",key,len);
free(keyb);

  fclose(fp);
}
